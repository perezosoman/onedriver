# onedriver — Configuration Reference

Config file location: `~/.config/onedriver/config.yml` (YAML format)

All parameters are optional — onedriver uses sensible defaults for everything.

## Quick start example

```yaml
# ~/.config/onedriver/config.yml
log: info
cacheDir: ~/.cache/onedriver
cacheMaxAge: 720h
```

## Top-level parameters

### `log`

Log verbosity level.

| Value   | Description |
|---------|-------------|
| `trace` | Every syscall handled by the filesystem |
| `debug` | All operations that modify a file or directory |
| `info`  | "Big" operations like uploads and downloads |
| `warn`  | Warnings — usually not a problem |
| `error` | Errors onedriver can recover from |
| `fatal` | Only fatal errors (not recommended) |

**Default:** `debug`

```yaml
log: info
```

### `cacheDir`

Directory where onedriver stores its cache (metadata database + downloaded file content). Can grow large depending on usage. `~` is expanded to your home directory.

**Default:** `~/.cache/onedriver`

```yaml
cacheDir: ~/.cache/onedriver
```

### `cacheMaxAge` (since onedriver X.Y)

Maximum age of cached file content before automatic eviction. When set, a
background goroutine periodically removes content files whose last
modification time exceeds this duration. Files currently open (being read or
written) are skipped.

Set to `0` or omit to disable eviction entirely (files stay cached forever).

Format: Go duration string — a number followed by a unit suffix.

| Suffix | Unit |
|--------|------|
| `s`    | seconds |
| `m`    | minutes |
| `h`    | hours |
| `d`    | days (24h) |

Examples:

```yaml
# Evict content not accessed in 30 days
cacheMaxAge: 720h

# Evict after 1 day
cacheMaxAge: 24h

# Evict after 7 days
cacheMaxAge: 168h

# Disabled (default)
cacheMaxAge: 0
```

Evicted files are re-downloaded transparently from OneDrive the next time
they are accessed. Metadata (file names, sizes, directory structure) is
**not** evicted — only the downloaded content.

## `auth` section

OAuth2 authentication parameters. You should **not** change these unless you
have registered your own application in Azure Active Directory / Entra ID.
The defaults point to the official onedriver app registration.

```yaml
auth:
  clientID: "3470c3fa-bc10-45ab-a0a9-2d30836485d1"
  codeURL: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
  tokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token"
  redirectURL: "https://login.live.com/oauth20_desktop.srf"
```

### `auth.clientID`

Azure AD / Entra ID application (client) ID.

**Default:** `3470c3fa-bc10-45ab-a0a9-2d30836485d1`

### `auth.codeURL`

OAuth2 authorization endpoint.

**Default:** `https://login.microsoftonline.com/common/oauth2/v2.0/authorize`

### `auth.tokenURL`

OAuth2 token endpoint.

**Default:** `https://login.microsoftonline.com/common/oauth2/v2.0/token`

### `auth.redirectURL`

OAuth2 redirect URI (must match the one registered in Azure AD).

**Default:** `https://login.live.com/oauth20_desktop.srf`

## Complete example

```yaml
log: info
cacheDir: ~/.cache/onedriver
cacheMaxAge: 720h

# Only uncomment if using your own Azure AD app registration
#auth:
#  clientID: "your-client-id-here"
#  codeURL: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
#  tokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token"
#  redirectURL: "https://login.live.com/oauth20_desktop.srf"
```

## CLI overrides

These config values can be overridden at runtime via command-line flags:

| Config key   | CLI flag          |
|-------------|-------------------|
| `cacheDir`  | `--cache-dir` / `-c` |
| `log`       | `--log` / `-l`    |

`cacheMaxAge` and `auth.*` have no CLI equivalents.
