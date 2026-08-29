# Bring your existing `.env`

Already have a `.env` for your app? You don't have to retype it. Import it once and Mooring takes over managing the live environment from there.

See also: [Secrets & config files](./config-files-and-secrets.md) · [Deploy your first app](./first-steps.md)

---

## The idea

Mooring **owns the environment your app runs with**. A `.env` you provide is an *import source* — Mooring reads it, stores the values, and writes the real environment file itself at deploy time. Your original file is never the one the app runs, so there's a single source of truth.

When you import, Mooring sorts each value into one of two kinds:

- **Secrets** (passwords, API keys, tokens) — stored **encrypted** and write-only. They're injected into the app at runtime and never shown back in plain text. Mooring leans toward treating anything secret-shaped as a secret.
- **Plain settings** (log level, feature flags) — stored as ordinary values you can see and edit.

## Importing

**In the dashboard:** open your app → **Env**, and add values there directly. This is the easiest way for a few values.

**From a file (CLI):** for a big existing `.env`, import it in one go over SSH:

```bash
mooring secret import --slug my-app --from ./prod.env
```

Mooring parses the file, classifies each key, and stores everything. The values are read from the file — never passed on the command line.

If an import would **change a secret that's already set** (a rotation) or turn a secret into a plain value, Mooring holds those back and asks you to confirm them explicitly, so you can't overwrite a live credential by accident. Everything else applies normally.

## Referencing secrets in config

In your app's definition or config files, refer to a secret **by name** rather than pasting its value:

```yaml
env:
  DATABASE_URL: { secret: DATABASE_URL }
```

The actual value is set separately (dashboard or import) and supplied when the app runs. This keeps real credentials out of your YAML and out of your repo, so those files are safe to commit. A secret reference only ever resolves within the same app.
