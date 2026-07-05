package builder

import (
	"strings"
	"testing"
)

// must renders a Dockerfile or fails the test.
func must(t *testing.T, s Spec, files map[string]bool) string {
	t.Helper()
	df, err := Generate(s, files)
	if err != nil {
		t.Fatalf("Generate(%+v): %v", s, err)
	}
	return df
}

func mustHave(t *testing.T, df string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(df, w) {
			t.Errorf("Dockerfile missing %q:\n%s", w, df)
		}
	}
}

func mustNotHave(t *testing.T, df string, notWants ...string) {
	t.Helper()
	for _, w := range notWants {
		if strings.Contains(df, w) {
			t.Errorf("Dockerfile must NOT contain %q:\n%s", w, df)
		}
	}
}

// --- node: npm stays byte-identical to the historical output ---

func TestNodeNpmByteIdentical(t *testing.T) {
	// No lockfile, no explicit install → the exact pre-feature npm output.
	df := must(t, Spec{Language: "node", Start: []string{"node", "x"}, Nonroot: true}, nil)
	mustHave(t, df,
		"COPY package*.json ./",
		"RUN npm install",
		"RUN npm prune --omit=dev",
	)
	mustNotHave(t, df, "corepack", "pnpm", "yarn")

	// A committed package-lock.json is still npm (byte-identical manifests glob).
	df2 := must(t, Spec{Language: "node", Start: []string{"node", "x"}}, map[string]bool{"package.json": true, "package-lock.json": true})
	mustHave(t, df2, "COPY package*.json ./", "RUN npm install", "RUN npm prune --omit=dev")
	mustNotHave(t, df2, "corepack", "pnpm", "yarn")
}

// --- node: pnpm ---

func TestNodePnpm(t *testing.T) {
	df := must(t, Spec{Language: "node", Start: []string{"pnpm", "start"}, Nonroot: true},
		map[string]bool{"package.json": true, "pnpm-lock.yaml": true})
	mustHave(t, df,
		"ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0",
		"RUN corepack enable",
		"COPY package.json pnpm-lock.yaml ./",
		"RUN pnpm install --frozen-lockfile",
		"RUN pnpm prune --prod",
	)
	mustNotHave(t, df, "npm prune --omit=dev", "COPY package*.json ./")
	// The runtime stage must also provision pnpm (node:alpine doesn't bundle it), else a
	// `pnpm start` CMD ships a crash-on-start image. It must land in the run stage, with
	// pnpm's version self-switch disabled so a packageManager pin doesn't force a
	// download at container start.
	runStage := df[strings.Index(df, "AS run"):]
	mustHave(t, runStage,
		"ENV npm_config_manage_package_manager_versions=false",
		"RUN npm install -g pnpm",
		`CMD ["pnpm", "start"]`,
	)
}

// Yarn Berry (v2+): .yarnrc.yml beside yarn.lock → --immutable, copy-all-before-install
// (so .yarn/releases resolve), no v1 --production prune, Corepack-provisioned.
func TestNodeYarnBerry(t *testing.T) {
	df := must(t, Spec{Language: "node", Start: []string{"node", "x"}},
		map[string]bool{"package.json": true, "yarn.lock": true, ".yarnrc.yml": true})
	mustHave(t, df, "RUN corepack enable", "RUN yarn install --immutable", "COPY . .")
	// No classic-v1 commands, and no manifest-first COPY (Berry needs the full context).
	mustNotHave(t, df, "--frozen-lockfile", "--production", "COPY package.json yarn.lock ./")
}

// --- node: yarn (classic; bundled — no corepack) ---

func TestNodeYarn(t *testing.T) {
	df := must(t, Spec{Language: "node", Start: []string{"node", "x"}},
		map[string]bool{"package.json": true, "yarn.lock": true})
	mustHave(t, df,
		"COPY package.json yarn.lock ./",
		"RUN yarn install --frozen-lockfile",
		"RUN yarn install --production --ignore-scripts --prefer-offline",
	)
	mustNotHave(t, df, "corepack", "npm prune", "pnpm")
}

// An explicit build.install naming a manager selects it even without a lockfile, and
// the prune matches that manager.
func TestNodePMFromInstallCommand(t *testing.T) {
	df := must(t, Spec{Language: "node", Install: "pnpm install --foo", Start: []string{"node", "x"}}, nil)
	mustHave(t, df, "RUN corepack enable", "RUN pnpm install --foo", "RUN pnpm prune --prod", "COPY package*.json ./")
}

// A lockfile-selected manager whose prune is opted out of when the operator overrides
// install with an UNRELATED manager (mirrors the historical npm-only prune gate).
func TestNodePruneGatedByEffectiveManager(t *testing.T) {
	// pnpm lockfile but operator forces npm → no prune of either (mismatch → skip).
	df := must(t, Spec{Language: "node", Install: "npm ci", Start: []string{"node", "x"}},
		map[string]bool{"package.json": true, "pnpm-lock.yaml": true})
	mustHave(t, df, "RUN npm ci", "COPY package.json pnpm-lock.yaml ./")
	mustNotHave(t, df, "prune")
}

// --- static: pnpm build stage, output-only ship, no prune ---

func TestStaticPnpm(t *testing.T) {
	df := must(t, Spec{Language: "static", Build: "pnpm run build", Output: "dist"},
		map[string]bool{"index.html": true, "package.json": true, "pnpm-lock.yaml": true})
	mustHave(t, df,
		"RUN corepack enable",
		"COPY package.json pnpm-lock.yaml ./",
		"RUN pnpm install --frozen-lockfile", // defaulted install for the SPA
		"RUN pnpm run build",
		"COPY --from=build /app/dist /usr/share/nginx/html",
	)
	// node_modules is discarded with the build stage — never a prune step.
	mustNotHave(t, df, "prune")
}

// --- python: pip byte-identical; poetry & pipenv counterparts ---

func TestPythonPipByteIdentical(t *testing.T) {
	df := must(t, Spec{Language: "python", Start: []string{"python", "app.py"}, Nonroot: true},
		map[string]bool{"requirements.txt": true})
	mustHave(t, df, "RUN pip install --no-cache-dir -r requirements.txt")
	mustNotHave(t, df, "poetry", "pipenv")
}

func TestPythonPoetry(t *testing.T) {
	df := must(t, Spec{Language: "python", Start: []string{"python", "app.py"}},
		map[string]bool{"pyproject.toml": true, "poetry.lock": true})
	mustHave(t, df,
		"pip install --no-cache-dir poetry",
		"poetry config virtualenvs.create false",
		"poetry install --only main --no-root",
	)
}

func TestPythonPipenv(t *testing.T) {
	df := must(t, Spec{Language: "python", Start: []string{"python", "app.py"}},
		map[string]bool{"Pipfile": true, "Pipfile.lock": true})
	mustHave(t, df, "pip install --no-cache-dir pipenv", "pipenv install --deploy --system")
}

// A Pipfile with NO committed lock must not use --deploy (which hard-fails on a missing
// or stale lock) — it installs and generates the lock in-build instead.
func TestPythonPipenvNoLock(t *testing.T) {
	df := must(t, Spec{Language: "python", Start: []string{"python", "app.py"}},
		map[string]bool{"Pipfile": true})
	mustHave(t, df, "pipenv install --system")
	mustNotHave(t, df, "--deploy")
}

// --- unit: detection helpers ---

func TestDetectJSPM(t *testing.T) {
	cases := []struct {
		files   map[string]bool
		install string
		want    string
	}{
		{map[string]bool{"pnpm-lock.yaml": true}, "", "pnpm"},
		{map[string]bool{"yarn.lock": true}, "", "yarn"},
		{map[string]bool{"package-lock.json": true}, "", "npm"},
		{nil, "", "npm"},
		{nil, "pnpm install", "pnpm"},
		{nil, "yarn", "yarn"},
		{nil, "npm ci", "npm"},
		// lockfile beats the install command word
		{map[string]bool{"yarn.lock": true}, "pnpm install", "yarn"},
	}
	for _, c := range cases {
		if got := detectJSPM(c.files, c.install).name; got != c.want {
			t.Errorf("detectJSPM(%v, %q) = %s, want %s", c.files, c.install, got, c.want)
		}
	}
}

func TestFirstWord(t *testing.T) {
	for in, want := range map[string]string{
		"npm install":   "npm",
		"  pnpm  ":      "pnpm",
		"yarn\tinstall": "yarn",
		"":              "",
	} {
		if got := firstWord(in); got != want {
			t.Errorf("firstWord(%q) = %q, want %q", in, got, want)
		}
	}
}
