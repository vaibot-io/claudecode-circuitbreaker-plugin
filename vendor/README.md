# Vendored dependencies

## `vaibot-guard/` — a committed, real-file copy of `@vaibot/guard`

**Current version: `1.0.2`** (keep in lockstep with the version the `vaibot` CLI
installs globally and with the codex/openclaw plugin vendors).

### Why this is vendored

Claude Code installs a plugin by **copying its files** into `~/.claude/plugins/cache/`
and runs **no `npm install`** — so bare `@vaibot/guard/*` imports in the hooks would
throw `ERR_MODULE_NOT_FOUND`. The guard is committed here and the hooks import it by
**relative path** (`../vendor/vaibot-guard/scripts/...`), making the plugin
self-contained.

Two hard requirements:

- **Real files, no symlinks** — copies must never be a pnpm/workspace symlink (some
  copy steps drop symlinks). Refresh only via `npm pack`.
- **Same version as the CLI-installed guard** — a version skew can break the per-host
  single-guard adopt-not-duplicate invariant.

### Refresh after an `@vaibot/guard` release

```sh
cd packages/claudecode-circuitbreaker-plugin
npm pack @vaibot/guard@<version>
rm -rf vendor/vaibot-guard && mkdir -p vendor/vaibot-guard
tar xzf vaibot-guard-<version>.tgz && cp -RL package/. vendor/vaibot-guard/ && rm -rf package vaibot-guard-<version>.tgz
find vendor/vaibot-guard -type l    # must print nothing
node --test test/*.test.mjs
```

Then update the version above and `devDependencies["@vaibot/guard"]` in `package.json`.
