# dotvault

SSH-key encrypted, **namespaced** secret vault that exports to `.env` format.

`dotvault` stores passwords, API tokens, and other secrets **centrally** under
`~/.dotvault/namespaces/<ns>/`, encrypted with a key derived from your SSH
private key. Each project binds to a **namespace** via a plaintext
`.dotvault_key` file and reads its secrets as `KEY=VALUE` lines — ready to
redirect into a `.env` file or pipe into `env`/`direnv`.

## How it works

```
                          ┌──────────── centralized storage ────────────┐
  project A/              │  ~/.dotvault/namespaces/                     │
    .dotvault_key ───────►│    app-prod/  vault.bin   (SSH-key sealed)   │
   (namespace +           │               .access_key.enc (SSH-key enc)  │
    access_key,           │    app-stage/ vault.bin                      │
    plaintext)            │    ci-tokens/ vault.bin                      │
                          └─────────────────────────────────────────────┘
       + SSH key ──► decrypts the namespace's vault.bin every operation
```

- **SSH key** — required every operation; it decrypts a namespace's vault. The
  real secret-keeper.
- **access_key** — a namespace selector + authorization token. Stored plaintext
  in the project's `.dotvault_key` AND, encrypted by the SSH key, in the
  namespace's `.access_key.enc` registry. On every operation dotvault verifies
  the two match — so a project can't impersonate another namespace by editing
  its file.
- **Crypto:** AES-256-GCM. The whole `.env` document per namespace is one
  authenticated ciphertext; any tamper or wrong-key decrypt fails.

## Install

**One line (macOS / Linux):**

```sh
curl -fsSL https://raw.githubusercontent.com/oliveagle/dotvault/main/scripts/install.sh | bash
```

Then add `~/.dotvault/bin` to your `PATH` and run `dotvault install`.

**From source:**

```sh
cargo build --release   # binary at target/release/dotvault
```

**Prebuilt binaries:** see [Releases](https://github.com/oliveagle/dotvault/releases)
for `dotvault-Darwin-arm64.tar.gz`, `dotvault-Linux-x86_64.tar.gz`,
`dotvault-Windows-x86_64.zip`, etc.

## Requirements

- An SSH private key in **OpenSSH** format (`BEGIN OPENSSH PRIVATE KEY`).
  Legacy `BEGIN RSA PRIVATE KEY` / `BEGIN EC PRIVATE KEY` must first be
  converted: `ssh-keygen -p -m PEM -f ~/.ssh/id_rsa`.

## Quick start

```sh
dotvault install                 # one-time: create ~/.dotvault/ + config
dotvault init myapp              # bind THIS project to namespace "myapp"
                                 # → creates ~/.dotvault/namespaces/myapp/
                                 # → writes ./.dotvault_key

dotvault set DB_PASSWORD s3cret  # store a secret in namespace "myapp"
dotvault set API_TOKEN ghp_xyz

dotvault list                    # secret names (global + project sections)
dotvault export                  # KEY=VALUE from global + project, sectioned
dotvault export > .env           # write a .env file (comments are ignored)
dotvault get API_TOKEN           # value only, no trailing newline
```

`export` and `list` merge the global namespace with the project's namespace,
separated by `# === <ns> ===` comment headers (ignored by `.env` tools).
Project keys override global ones on name collisions:

```
# === global ===
GITHUB_TOKEN=ghp_xxx

# === namespace: myapp ===
DB_PASSWORD=s3cret
GITHUB_TOKEN=ghp_project_specific   # overrides the global one
```

Capture a single secret in a shell:

```sh
TOKEN=$(dotvault get API_TOKEN)
```

Load everything into the current shell:

```sh
eval "$(dotvault export | sed 's/^/export /')"
```

## Commands

```
dotvault install                       # bootstrap global dirs + config (idempotent)
dotvault init <NAMESPACE>              # create namespace + bind project (.dotvault_key)
dotvault set <KEY> <VALUE>             # add a secret (errors if KEY exists — rm first)
dotvault get <KEY>                     # value to stdout, no trailing newline
dotvault rm <KEY>                      # remove a secret (errors if absent)
dotvault list                          # secret names, global + project sections
dotvault export                        # KEY=VALUE from global + project, sectioned
dotvault ns list                       # list all namespaces
dotvault ns remove <NAMESPACE>         # delete a namespace (needs SSH key)
dotvault rekey --new-key <PATH>        # re-encrypt ALL namespaces with a new SSH key
dotvault version                       # print version + git hash + build details
dotvault doctor                        # verify current namespace integrity
dotvault config [--set-key ...]        # show/set ~/.dotvault/config.toml
```

**Upgrading** (not a subcommand — a separate script, since the binary can't
replace itself while running):

```sh
scripts/upgrade.sh                     # idempotent: no-op if already latest
```

Top-level option (must precede the subcommand):

```
--key <PATH>   SSH private key (default ~/.ssh/id_ed25519, env DOTVAULT_KEY)
```

## Namespaces & access keys

Each **namespace** is an isolated secret store. A project binds to one via a
`.dotvault_key` file at its root:

```text
# ./.dotvault_key  (plaintext, two lines)
myapp
a3f0c1b2...64-hex-chars
```

- `dotvault init <ns>` creates the namespace and writes this file.
- Multiple projects can share a namespace by copying the file between them.
- Switch a project's namespace by running `dotvault init <other>` again (it
  overwrites `.dotvault_key`) or by editing the file.
- Namespace names match `[a-z0-9][a-z0-9-_]*` (strictly validated — this is the
  path-traversal defense).

## Configuration

`~/.dotvault/config.toml` (optional — absent means pure defaults):

```toml
key = "~/.ssh/id_ed25519"        # default SSH key (saves typing --key)
backup_dir = "~/.dotvault/backups"
backup_keep = 50                 # keep newest N backups; 0 = unlimited
```

```sh
dotvault config                              # show effective config
dotvault config --set-key ~/.ssh/id_rsa      # set default key
dotvault config --set-backup-keep 50         # enable rotation
```

Resolution priority, highest first: `--flag` → env var → config file → default.
Env overrides: `DOTVAULT_KEY`, `DOTVAULT_HOME`, `DOTVAULT_BACKUP_DIR`,
`DOTVAULT_CONFIG`, `DOTVAULT_KEY_FILE`.

## Fail-fast behavior (no implicit actions)

Everything either succeeds explicitly or errors out — **the only implicit
action is the backup**.

| Situation                                  | Behavior                              |
|--------------------------------------------|---------------------------------------|
| `init <ns>` when namespace exists          | **error**                             |
| `set KEY` where KEY already exists         | **error** — `rm` first to replace     |
| `get`/`rm` a missing KEY                   | **error**                             |
| `.dotvault_key` access_key ≠ registered    | **error** — authorization rejected    |
| `.dotvault_key` names a non-existent ns    | **error**                             |
| SSH key fingerprint ≠ namespace's key      | **error** — wrong key / use `rekey`    |
| Decryption/GCM tag mismatch                | **error** — tampered or wrong key     |
| namespace name with `/`, `..`, uppercase   | **error** — invalid name              |

## Concurrency

Each namespace has an **exclusive lock** (an atomically-created `.lock` file)
held for the entire read-modify-write cycle of a write command (`init`/`set`/
`rm`/`rekey`). Concurrent processes writing the same namespace **serialize** —
no lost updates. Locks are per-namespace (writing `app-a` never blocks
`app-b`). If a lock can't be acquired within 30s (e.g. a crashed process left
it stale), dotvault errors with the lock path so you can `rm` it.

## File layout

```
~/.dotvault/
  config.toml                          # optional global config
  backups/                             # timestamped, ns-prefixed encrypted backups
    app-20260701-120000-a3f0c1.bin
  namespaces/
    <ns>/
      vault.bin                        # DV1 container (AES-256-GCM sealed)
      vault.meta.json                  # {version, ssh_fingerprint, kdf_salt, ...}
      .access_key.enc                  # access_key, encrypted by the SSH key
./.dotvault_key                        # project binding (plaintext namespace + key)
```

Each successful write backs up the previous container before installing the new
one (atomic temp + rename).

## Development

```sh
cargo test                            # unit + integration tests
./scripts/quality-gate.sh --all       # fmt + clippy + tests + coverage >80%
dotvault version                      # show version + git hash + build details
```

Quality gate runs on every push and PR (`.github/workflows/ci.yml`) on macOS,
Linux, and Windows; releases build on `v*` tags
(`.github/workflows/release.yml`).

### Releasing a new version

```sh
./scripts/bump.sh patch    # 0.2.0 → 0.2.1 (also: minor, major)
```

This bumps `Cargo.toml`/`Cargo.lock`, runs `cargo check`, commits
`release vX.Y.Z`, tags `vX.Y.Z`, and pushes — which triggers the release
workflow to build and publish platform binaries.

### Upgrading an install

```sh
scripts/upgrade.sh          # idempotent: no-op if already latest
# or re-run the installer:
curl -fsSL https://raw.githubusercontent.com/oliveagle/dotvault/main/scripts/install.sh | bash
```

`dotvault version` also checks online (cached 1h) and prints an `update: vX.Y.Z
available` line to stderr when a newer release exists.

## License

MIT
