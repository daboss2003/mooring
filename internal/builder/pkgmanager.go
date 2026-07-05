package builder

import "strings"

// Package-manager detection. A stack's language pins the base image and build shape;
// WITHIN a language there is often a choice of dependency manager (npm/yarn/pnpm for
// node, pip/poetry/pipenv for python). The committed lockfile is authoritative — it's
// the operator's declared intent and guarantees the file the COPY needs exists. When
// there is no lockfile, an explicit build.install command that names a manager selects
// it; otherwise the ecosystem default (npm, pip) applies so existing apps are unchanged.

// jsPM is a JavaScript package manager the node/static builders target.
type jsPM struct {
	name    string // npm | yarn | pnpm — also the RUN-line gate for the prune step
	install string // default install command (used ONLY when build.install is unset)
	prune   string // strips devDependencies from node_modules in place (node builder); "" = none
	// corepack provisions the manager in the BUILD stage via Corepack (pnpm, Yarn Berry) —
	// npm and classic Yarn are baked into node:alpine, so they need nothing.
	corepack bool
	// runtime is a RUN command that provisions the manager in the RUNTIME stage (node
	// builder), so a container whose start command invokes it (e.g. `pnpm start`) doesn't
	// crash with "not found". "" when the base image already has it (npm, classic Yarn —
	// and Yarn Berry, which the bundled yarn shim delegates to via the copied .yarnrc.yml).
	runtime string
	// copyAll copies the whole build context BEFORE install instead of manifests-first.
	// Yarn Berry needs .yarnrc.yml + .yarn/releases present to resolve `yarn`, which a
	// manifest-only COPY wouldn't include; the cost is losing the cached install layer.
	copyAll bool
	// manifests are the files COPYed before the source so the install layer caches
	// independently (ignored when copyAll).
	manifests []string
}

// detectJSPM chooses the JS package manager for a node/static build. pnpm-lock.yaml →
// pnpm, yarn.lock → yarn (Berry when a .yarnrc.yml sits beside it, else classic); both
// authoritative. With no lockfile an explicit build.install starting with pnpm/yarn
// selects it; otherwise npm. The npm result is byte-identical to the historical output
// (manifests = the package*.json glob), so existing npm apps never churn.
func detectJSPM(files map[string]bool, install string) jsPM {
	switch {
	case files["pnpm-lock.yaml"]:
		return jsPM{
			name: "pnpm", install: "pnpm install --frozen-lockfile", prune: "pnpm prune --prod",
			corepack: true, runtime: "npm install -g pnpm", manifests: []string{"package.json", "pnpm-lock.yaml"},
		}
	case files["yarn.lock"] && files[".yarnrc.yml"]:
		// Yarn Berry (v2+): --immutable is the frozen-lockfile equivalent; Berry's
		// node_modules pruning is linker-dependent and needs a plugin, so ship all deps
		// rather than risk a broken build. Corepack (or the committed .yarn release the
		// bundled yarn shim delegates to) provisions the pinned Yarn.
		return jsPM{name: "yarn", install: "yarn install --immutable", corepack: true, copyAll: true}
	case files["yarn.lock"]:
		return jsPM{
			name: "yarn", install: "yarn install --frozen-lockfile",
			prune: "yarn install --production --ignore-scripts --prefer-offline", manifests: []string{"package.json", "yarn.lock"},
		}
	case files["package-lock.json"], files["npm-shrinkwrap.json"]:
		return npmPM()
	}
	// No lockfile: honour an explicit manager in build.install, else default to npm.
	switch firstWord(install) {
	case "pnpm":
		return jsPM{name: "pnpm", install: "pnpm install", prune: "pnpm prune --prod", corepack: true, runtime: "npm install -g pnpm", manifests: []string{"package*.json"}}
	case "yarn":
		return jsPM{name: "yarn", install: "yarn install", prune: "yarn install --production --ignore-scripts --prefer-offline", manifests: []string{"package*.json"}}
	}
	return npmPM()
}

func npmPM() jsPM {
	return jsPM{name: "npm", install: "npm install", prune: "npm prune --omit=dev", manifests: []string{"package*.json"}}
}

// pyPM is a Python dependency manager the python builder targets. All install into the
// system interpreter (no venv) so the container's start command runs unchanged.
type pyPM struct {
	name    string // pip | poetry | pipenv
	install string // default install command (used ONLY when build.install is unset)
}

// detectPyPM chooses the Python dependency manager: poetry.lock → poetry, a Pipfile →
// pipenv, otherwise pip. poetry/pipenv are installed via pip then told to install the
// project's PRODUCTION dependencies into system site-packages. pipenv only uses --deploy
// (which requires an up-to-date lock) when a Pipfile.lock is committed. The pip result
// is byte-identical to the historical output.
func detectPyPM(files map[string]bool) pyPM {
	switch {
	case files["poetry.lock"]:
		return pyPM{"poetry", "pip install --no-cache-dir poetry && poetry config virtualenvs.create false && poetry install --only main --no-root"}
	case files["Pipfile.lock"]:
		return pyPM{"pipenv", "pip install --no-cache-dir pipenv && pipenv install --deploy --system"}
	case files["Pipfile"]:
		// No lockfile → pipenv generates one during install; --deploy would hard-fail.
		return pyPM{"pipenv", "pip install --no-cache-dir pipenv && pipenv install --system"}
	}
	return pyPM{"pip", "pip install --no-cache-dir -r requirements.txt"}
}

// firstWord returns the first whitespace-delimited token of a command (its program).
func firstWord(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}

// srcJoin renders a space-separated COPY source list, each element scoped to the build
// subdir (Spec.src). With no build.dir this is byte-identical to the bare names.
func srcJoin(s Spec, names []string) string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = s.src(n)
	}
	return strings.Join(out, " ")
}
