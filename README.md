# dotvault

SSH-key encrypted, **multi-recipient** secret vault that exports to `.env`
format. Each project keeps its own encrypted `.vault` file **committed to
git**, and every authorized teammate can decrypt it with their own SSH key.

`dotvault` stores passwords, API tokens, and other secrets in a project-local
`.vault` file (an [age](https://age-encryption.org) container encrypted to the
SSH public keys of every authorized recipient). The list of authorized keys
lives in `.vault.keys` (JSON, also committed). Anyone on the team whose key is
listed can decrypt; adding/removing a teammate is one command.

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

## Commands

```
dotvault install                       # bootstrap global dirs + config (idempotent)
dotvault init                          # create project .vault + .vault.keys (your key)
dotvault set <KEY> <VALUE>             # add a secret (errors if KEY exists — rm first)
dotvault get <KEY>                     # value to stdout, no trailing newline
dotvault rm <KEY>                      # remove a secret (errors if absent)
dotvault list                          # secret names
dotvault export                        # KEY=VALUE
dotvault add-key <PUBKEY>              # authorize a teammate (pubkey line / *.pub / @file)
dotvault remove-key <FP|LABEL>         # revoke a teammate (re-encrypts; see Security)
dotvault list-keys                     # list authorized recipients (fingerprints + labels)
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
--key <PATH>   SSH private key (default ~/.ssh/id_ed25519, env DOTVAULT_KEY)
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
  .vault                # age container, encrypted to all authorized keys (committed)
  .vault.keys           # authorized-public-key registry, JSON (committed)
  .vault.lock           # exclusive lock (gitignored, transient)

~/.dotvault/            # global, no secrets
  config.toml           # optional config
  backups/              # timestamped, project-prefixed encrypted backups
    myapp-20260701-120000-a3f0c1.bin
```

Each successful write backs up the previous `.vault` before installing the new
one (atomic temp + rename).

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
curl -fsSL https://raw.githubusercontent.com/oliveagle/dotvault/main/scripts/install.sh | bash
```

`dotvault version` also checks online (cached 1h) and prints an `update: vX.Y.Z
available` line to stderr when a newer release exists.

## License

MIT
