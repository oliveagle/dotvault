# dotvault

SSH-key encrypted, **multi-recipient** secret vault that exports to `.env`
format. Each project keeps its own encrypted `.vault` file **committed to
git**, and every authorized teammate can decrypt it with their own SSH key.
A read-only **token** mode lets CI/automation read secrets without an SSH key.

`dotvault` stores passwords, API tokens, and other secrets in a project-local
`.vault` file (an [age](https://age-encryption.org) container encrypted to the
SSH public keys of every authorized recipient, plus any read-only tokens). The
list of authorized keys lives in `.vault.keys` (JSON, also committed). Anyone
on the team whose key is listed can decrypt; adding/removing a teammate is one
command.

## How it works

```
  project/                    committed to git
    .vault       ───────────► age container (encrypted to every authorized key)
    .vault.keys  ───────────► { authorized public keys }   (auditable)

  ~/.ssh/id_ed25519  ──► your private key decrypts .vault (one of N recipients)
```

- **`.vault`** — the encrypted secrets. An age file encrypted to every public
  key in `.vault.keys`. Any single authorized private key decrypts it.
- **`.vault.keys`** — the authorized-public-key registry (human-readable JSON,
  committed to git). Source of truth for who can decrypt. Add a teammate =
  append their key + re-encrypt.
- **No central secret store.** `~/.dotvault/` holds only config, backups, and
  the update-check cache — no secrets.

## Install

**One line (macOS / Linux):**

```sh
curl -fsSL https://raw.githubusercontent.com/oliveagle/dotvault/main/install.sh | bash
```

This downloads the latest release binary, verifies its SHA-256 checksum, and
installs it to `~/.dotvault/bin/dotvault`. Idempotent — re-run to upgrade.

Then add `~/.dotvault/bin` to your `PATH` (one-time, pick your shell):

```sh
echo 'export PATH="$HOME/.dotvault/bin:$PATH"' >> ~/.zshrc   # or ~/.bashrc
source ~/.zshrc
dotvault install          # one-time: create ~/.dotvault/ + default config
```

**From source (requires Rust toolchain):**

```sh
git clone https://github.com/oliveagle/dotvault.git
cd dotvault
make install              # = cargo build --release + install to ~/.dotvault/bin
```

**Prebuilt binaries:** see [Releases](https://github.com/oliveagle/dotvault/releases)
for `dotvault-Darwin-arm64.tar.gz`, `dotvault-Linux-x86_64.tar.gz`,
`dotvault-Windows-x86_64.zip`, etc.

## Requirements

- An SSH private key in **OpenSSH** format (`BEGIN OPENSSH PRIVATE KEY`).
  Legacy `BEGIN RSA PRIVATE KEY` / `BEGIN EC PRIVATE KEY` must first be
  converted: `ssh-keygen -p -m PEM -f ~/.ssh/id_rsa`.
- A matching `*.pub` file is convenient for `init` (otherwise the public key
  is derived from the private key).

## Quick start

```sh
dotvault install                 # one-time: create ~/.dotvault/ + config

cd my-project/
dotvault init                    # create .vault + .vault.keys, seeded with YOUR key
dotvault set DB_PASSWORD s3cret  # store a secret
dotvault set API_TOKEN ghp_xyz

dotvault list                    # secret names
dotvault export                  # KEY=VALUE
dotvault export > .env           # write a .env file (gitignored)
dotvault get API_TOKEN           # value only, no trailing newline
```

Render a config template (substitute `{{KEY}}` placeholders with secrets):

```sh
# config.yaml.tmpl:
#   database:
#     password: {{DB_PASSWORD}}
#   api_key: {{ API_TOKEN }}
dotvault render config.yaml.tmpl              # → stdout
dotvault render config.yaml.tmpl --out config.yaml   # write file, mode 0600
```

### Sharing with a teammate

```sh
# You authorize Bob by his public key:
dotvault add-key ~/.ssh/bob_id_ed25519.pub   # or an authorized-keys line, or @file

# Bob commits the updated .vault + .vault.keys, pulls, and decrypts with HIS key:
dotvault get DB_PASSWORD                      # works with Bob's ~/.ssh/id_ed25519
```

Capture a single secret in a shell:

```sh
TOKEN=$(dotvault get API_TOKEN)
```

Load everything into the current shell:

```sh
eval "$(dotvault export | sed 's/^/export /')"
```

### Read-only tokens for CI

Generate a read-only token (it's an `AGE-SECRET-KEY-1...` string), then store
it as a secret in your CI (GitHub Actions secrets, GitLab CI variables, etc.).
CI uses `--token` (or `DOTVAULT_TOKEN` env) to read — it CANNOT write:

```sh
# On your laptop (needs your SSH key):
dotvault add-token ci-deploy                  # prints AGE-SECRET-KEY-1... ONCE — copy it
# → paste into CI as secret DOTVAULT_TOKEN

# In CI (no SSH key needed, read-only):
dotvault --token "$DOTVAULT_TOKEN" export > .env
dotvault --token "$DOTVAULT_TOKEN" get DB_PASSWORD
dotvault --token "$DOTVAULT_TOKEN" render config.yaml.tmpl --out config.yaml

# Manage tokens (SSH key required):
dotvault list-tokens                          # shows age1... public keys (never the secret)
dotvault revoke-token ci-deploy               # revoke: re-encrypts, token stops working immediately
```

A token grants full **read** of all secrets. "Read-only" is enforced at
runtime (write commands are rejected) — cryptographically a token can decrypt
everything an SSH key can, so treat a leaked token as seriously as a leaked
SSH key: revoke it and **rotate** any sensitive secret values. The token
secret is shown **once** at creation and is never stored; only its public key
(`age1...`) lives in `.vault.keys`.

## Commands

```
dotvault install                       # bootstrap global dirs + config (idempotent)
dotvault init                          # create project .vault + .vault.keys (your key)
dotvault set <KEY> <VALUE>             # add a secret (errors if KEY exists — rm first)
dotvault get <KEY>                     # value to stdout, no trailing newline
dotvault rm <KEY>                      # remove a secret (errors if absent)
dotvault list                          # secret names
dotvault export                        # KEY=VALUE
dotvault render <TEMPLATE> [--out F]   # substitute {{KEY}} in a template → stdout / file (0600)
dotvault add-key <PUBKEY>              # authorize a teammate (pubkey line / *.pub / @file)
dotvault remove-key <FP|LABEL>         # revoke a teammate (re-encrypts; see Security)
dotvault add-token <LABEL>             # create a read-only CI token (prints secret ONCE)
dotvault list-tokens                   # list read-only tokens (age1... public keys)
dotvault revoke-token <LABEL|age1...>  # revoke a token (re-encrypts; see Security)
dotvault list-keys                     # list authorized recipients + tokens
dotvault doctor                        # verify vault + list authorized keys
dotvault version                       # print version + git hash + build details
dotvault config [--set-key ...]        # show/set ~/.dotvault/config.toml
```

**Upgrading** (not a subcommand — a separate script, since the binary can't
replace itself while running):

```sh
scripts/upgrade.sh                     # idempotent: no-op if already latest
```

Top-level option (must precede the subcommand):

```
--key <PATH>     SSH private key (default ~/.ssh/id_ed25519, env DOTVAULT_KEY)
--token <TOKEN>  read-only access token for CI (env DOTVAULT_TOKEN). Mutually
                 exclusive with --key; rejects write commands.
```

## Security model

- **Encryption:** the `.vault` file is an [age](https://age-encryption.org/v1)
  container encrypted to every public key in `.vault.keys`. age uses an
  ephemeral file key per encryption with one recipient stanza per key
  (ChaCha20-Poly1305 AEAD). Supported key types: `ssh-ed25519`, `ssh-rsa`.
- **Authorization = key possession.** If your SSH private key is listed in
  `.vault.keys` (its public half), you can decrypt. No separate access token.
- **Adding a user** (`add-key`): re-encrypts the vault to the new full key set.
  Cheap — one new stanza, the whole payload re-sealed.
- **Removing a user** (`remove-key`): re-encrypts to the remaining keys.
  **Important:** this does NOT revoke access to ciphertext already committed to
  git history. A revoked user who has an old checkout can still decrypt old
  commits (the historical file key was wrapped to them). For a true revocation,
  also **rotate the secret values** (e.g. `set` new passwords/tokens) so the
  leaked-history ciphertext is worthless.
- **Who can change `.vault.keys`?** Anyone with repository write access (the
  key list is just a committed file). This is the same trust model as sops and
  git-crypt: repository access controls who can add/remove recipients.

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
`DOTVAULT_CONFIG`, `DOTVAULT_VAULT_DIR`.

## Fail-fast behavior (no implicit actions)

Everything either succeeds explicitly or errors out — **the only implicit
action is the backup**.

| Situation                                  | Behavior                              |
|--------------------------------------------|---------------------------------------|
| `init` when a `.vault` already exists      | **error**                             |
| `set KEY` where KEY already exists         | **error** — `rm` first to replace     |
| `get`/`rm` a missing KEY                   | **error**                             |
| `load` with a key not in `.vault.keys`     | **error** — decryption fails          |
| `add-key` a duplicate key                  | **error** — already authorized        |
| `remove-key` the last authorized key       | **error** — vault would be unrecoverable |
| Decryption failure                         | **error** — tampered or unauthorized  |

## Concurrency

The project `.vault` has an **exclusive lock** (an atomically-created
`.vault.lock` file, gitignored) held for the entire read-modify-write cycle of
a write command (`init`/`set`/`rm`/`add-key`/`remove-key`). Concurrent
processes writing the same project **serialize** — no lost updates. If a lock
can't be acquired within 30s (e.g. a crashed process left it stale), dotvault
errors with the lock path so you can `rm` it.

## File layout

```
project/
  .vault                  # age container, encrypted to all authorized keys (committed)
  .vault.keys             # authorized-key registry, JSON + top // agent-guidance comment (committed)
  .vault.lock             # exclusive lock (gitignored, transient)

~/.dotvault/              # global, no secrets
  config.toml             # optional config
  backups/                # timestamped, project-prefixed encrypted backups
    myapp-20260701-120000-a3f0c1.bin
```

Each successful write backs up the previous `.vault` before installing the new
one (atomic temp + rename).

### AI agent discovery

`.vault.keys` starts with a short `//` comment (stripped before JSON parsing)
pointing any AI agent (Claude Code, Codex, Cursor, aider, etc.) that reads the
file to `dotvault --help` for the full command reference. So an agent landing
in the project learns to fetch secrets via `dotvault get NAME` instead of
hardcoding them — no separate companion file or installed skill needed. The
command's own `--help` is the single source of truth, so it can never go stale.

## Migrating from v0.3 (centralized namespaces)

v0.4 is a **breaking change**: the centralized `~/.dotvault/namespaces/<ns>/`
storage and the `.dotvault_key` binding file are gone, replaced by
project-local `.vault` + `.vault.keys` using age multi-recipient encryption.
The old AES-GCM/HKDF single-key format is incompatible and **not auto-migrated**.

To migrate manually:

1. In each project, run `dotvault init` (creates a fresh `.vault`).
2. Re-add each secret: `dotvault set KEY VALUE` (read values from the old vault
   with the v0.3 binary first, if needed).
3. Authorize teammates: `dotvault add-key <their-pubkey>`.
4. Commit `.vault` + `.vault.keys`.

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
./scripts/bump.sh patch    # 0.4.0 → 0.4.1 (also: minor, major)
```

This bumps `Cargo.toml`/`Cargo.lock`, runs `cargo check`, commits
`release vX.Y.Z`, tags `vX.Y.Z`, and pushes — which triggers the release
workflow to build and publish platform binaries.

### Upgrading an install

```sh
scripts/upgrade.sh          # idempotent: no-op if already latest
# or re-run the installer:
curl -fsSL https://raw.githubusercontent.com/oliveagle/dotvault/main/install.sh | bash
```

`dotvault version` also checks online (cached 1h) and prints an `update: vX.Y.Z
available` line to stderr when a newer release exists.

## License

MIT
