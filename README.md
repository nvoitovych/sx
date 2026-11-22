<p align="center"><img src="App/Sources/Assets.xcassets/AppIcon.appiconset/icon_256x256.png" width="128" alt="sx icon"></p>

# sx — secrets your agents can use, not read

**sx** ("secrets exec") is a macOS menu bar app plus a command-line tool for developers who work with AI coding agents (Claude Code, Codex, Cursor, …).

Keys live in your iCloud Keychain — or in Bitwarden, 1Password, or a backend you plug in — not in `.env` files. Projects keep a `.env.sx` with references only. `sx run` gives the real values to the process you start, masks them in its output, and asks you first.

```console
$ sx import-env .env --prefix myapp --remove-original
✓ OPENAI_KEY → sx://myapp/OPENAI_KEY
✓ STRIPE_KEY → sx://myapp/STRIPE_KEY

$ sx run -- npm run dev          # you or your agent; Touch ID once per command
  ready on http://localhost:3000 with key <sx:OPENAI_KEY>

$ sx run -- printenv OPENAI_KEY  # what an agent gets if it tries to peek
sx: refused for Claude Code: `printenv` only prints the environment
```

> Status: **0.2, early.** Written by one developer, not independently audited. The Bitwarden and 1Password backends have not yet been exercised against real accounts. Read [Security model](#security-model) and [Limits](#limits) before trusting it with production keys.

## Why

Agents read files and terminal output, and what they read is sent to a model provider. A plain `.env` in the repo means keys end up in transcripts. sx keeps values out of files and out of output while the code that needs them still runs.

## Install

Download the DMG from [nvlab.co/sx](https://nvlab.co/sx/), drag **sx** to Applications, open it once. Then **Command line → Install** links `/usr/local/bin/sx` to the copy inside the app.

Requirements: macOS 14+, Apple silicon or Intel. iCloud Keychain on if you want secrets to follow you to other Macs.

## Use

### Keychain secrets (default vault)

```sh
sx put myapp/STRIPE_KEY --tag prod              # hidden prompt, or pipe the value on stdin
sx import-env .env --prefix myapp               # moves values in, writes .env.sx next to it
sx import-env .dev.vars --prefix myapp --literal LOG_LEVEL,FEATURE_X   # keep non-secrets as plain text
sx import-file ./AuthKey.p8 --name apple/asc    # any file
sx ls                                           # names only; values are never printed
sx verify myapp/STRIPE_KEY --file old.txt       # compares hashes
sx run -- npm test                              # reads .env.sx in the current directory
sx run --env-file deploy.env.sx -- make deploy
sx run --env API=sx://myapp/OPENAI_KEY -- ./script.sh
sx run --file .dev.vars -- wrangler dev         # tools that only read a file: it exists for the run only
sx export apple/asc --out ~/.appstoreconnect/AuthKey.p8   # put a key file back (human-only, Touch ID)
```

`.env.sx` is ordinary dotenv. `KEY=sx://name` is resolved, everything else passes through:

```dotenv
OPENAI_KEY=sx://myapp/OPENAI_KEY
CI_TOKEN=sx://@work/ci/token     # explicit vault
PORT=3000
```

### Several vaults

`~/.config/sx/config.toml` (no secrets in it) defines vaults and which directories use which:

```toml
default = "personal"            # the built-in iCloud Keychain vault

[vault.work]
backend = "bitwarden"
server  = "https://vault.example.com"   # optional; omit for bitwarden.com
cli     = "npx -y @bitwarden/cli@2025.12.1"  # optional; default `bw`
organization = "Acme"                  # optional; `sx put --vault work` files items here
collection   = "Engineering"           # optional default collection for `sx put`

[vault.client]
backend = "1password"
account = "client.1password.com"        # optional

[vault.hc]
backend = "plugin"
type    = "hashicorp"                   # runs `sx-backend-hashicorp`

[route]
"~/Developer/work/**"   = "work"
"~/Developer/client/**" = "client"
```

- **Bitwarden**: `sx login work` unlocks once (`bw` CLI) and keeps the session in the keychain; `sx run` asks before using it. Names are item names; `item#field` reads a custom field.
  A self-hosted server (e.g. Vaultwarden) can lag the newest `bw`: if login fails with `KDF config response does not contain a valid KDF type`, pin a CLI version that matches the server with `cli` for that vault only.
  `sx put NAME --vault work [--file P] [--about TEXT] [--collection C]` stores a new item: a multi-line value (a key, a certificate) becomes a secure note holding only the value, one line becomes a login password; `--about` goes into a text field `about`. With `organization` set the item lands in that organization's collection (`sx ls --vault work --collections` lists them). sx never overwrites an existing item, sends the item to `bw` on stdin (not in argv) and reads it back to compare by hash.
- **1Password**: names are `Vault/Item` or `Vault/Item/field`; `op` handles its own unlock.
- **Your own backend**: any executable, see [docs/plugins.md](docs/plugins.md).

`sx vaults` shows the configuration and which vault the current directory routes to.

### Agents and project allowlists

Under an agent, sx:

- refuses commands that only print the environment or run inline code: `env`, `printenv`, `sh -c`, `python -c`, `node -e`, …;
- never turns masking off (`--no-mask` is human-only);
- shows an approval card — who asks, which command, which project, which secrets — before releasing anything. Touch ID, then remembered for that exact command for 8 hours (configurable). Secrets tagged `prod` ask every time.

A project can pre-approve what agents may run with `.sx.toml`:

```toml
[agents]
allow   = ["npm run dev", "npm test", "wrangler deploy"]
require = true          # agents may run nothing else with secrets

[vault]
default = "work"        # optional: vault for this project's references
```

The file does nothing until a human runs `sx trust` (Touch ID). The approved digest is stored in the keychain, so any later edit — by you or an agent — un-trusts it until approved again.

### SSH agent

```sh
sx ssh import ~/.ssh/id_ed25519 --remove-original   # ed25519 and RSA, unencrypted OpenSSH format
sx ssh setup --write                                # IdentityAgent in ~/.ssh/config
ssh -T git@github.com
```

Private keys never leave Sx.app; `ssh` gets public keys and signatures. The first use of a key by a given caller shows a card with the process chain (e.g. `ssh ← git ← claude`). Passphrase-protected keys must be stored as an unencrypted copy — the keychain and Touch ID take the passphrase's role.

### Approving from a terminal (when Touch ID is out of reach)

Working on this Mac from a phone or another computer (a remote terminal, Orca mobile, SSH), you cannot touch Touch ID, so requests time out and `ssh` says `agent refused operation`. Turn on terminal approvals once, at the Mac:

```sh
sx approvals on          # Touch ID; stored in this Mac's keychain, not synced
```

Then, from any terminal on the Mac:

```console
$ sx pending
#7  sign in with ssh/id_ed25519 to the server with host key SHA256:3v… (caller calls it batman)  [timed out — approve and the next try passes]
     who:   Claude Code (AI agent)  ·  asked 13:05:12
     chain: ssh ← git ← zsh ← claude ← orca-provider-exec
     host:  host key SHA256:3v…  (the caller calls it batman)
     keys:  ssh/id_ed25519

$ sx approve 7 --for 8h
You are approving this request: …
and remembering, for 8 h (until about 21:06), every request of the same kind:
  #7 → Claude Code: logins with ssh/id_ed25519 to the server with host key SHA256:3v… only (the caller calls it batman)
macOS login password for nv:
✓ #7 approved — its next try passes; the same kind of request passes until 21:06
```

- `sx approve ID…` or `--all` approves once; a request that already timed out passes on its next try (within 15 min). `--for 8h` (at most 24 h) also remembers the same kind of request:
  - SSH login: this key **for that server only**, identified by the host key the server proves to the agent (`session-bind@openssh.com`, sent by OpenSSH 8.9+). The name the caller typed (`batman`) is shown but never trusted: anyone can repoint it in `~/.ssh/config`. Compare the host key fingerprint with the one you know.
  - `ssh-keygen -Y sign` (e.g. git commit signing): this key for that namespace (`git`).
  - `sx run`: this command line in this project with these secrets (what the command does can still change, e.g. `package.json` scripts).
  - Anything else (a login whose server is not verified, a forwarded agent, unknown data) can only be approved once while it waits. `--for 8h --any-host` allows the key for everything.
- Every listed request carries a token that `sx approve` sends back: if Sx.app restarted and the numbers were reused, the old number approves nothing. Text from the requester (command lines, paths, host names) is shown with control and invisible characters escaped and arguments shell-quoted.
- `sx grants` lists remembered approvals, `sx revoke ID` / `sx revoke --all` removes them (anyone may revoke). `sx approvals off` turns terminal approvals off; turning them on again needs Touch ID.
- Prod-tagged keys: once only, never `--for`, and no timed grant covers them. Deletes, exports (`sx export`) and `sx trust` stay Touch ID only.
- Sx.app checks the password (Open Directory), never the CLI, and the CLI sends it only after checking that the process behind the socket is Sx.app signed by the same team. It is read from the terminal with echo off; argv, environment and piped stdin are refused — the command fails without a terminal, so an agent that runs it gets told to hand it to you. 5 wrong passwords in 15 min lock it for 15 min; 10 in 24 h (successes in between do not reset that) turn terminal approvals off until Touch ID. After an approval you are told how many wrong passwords came since your last one. Every approval, grant and wrong password goes to the audit log.
- Anyone may run `sx pending`, and an agent may even start `sx approve`: the gate is the password, which only you know.

> **Type the password only into a terminal you opened yourself** (e.g. an Orca terminal pane you created), after you typed `sx approve` there. A process that owns a terminal (pty) reads every keystroke: never type it into a terminal or a prompt an agent created or wrapped (`script`, `expect`, a tmux session it started, a terminal it opened via `orca terminal create`), and never paste it into a chat. Check what the command prints before typing: it lists exactly which requests and which scope you approve.

## Security model

- **Storage**: keychain items in the data-protection keychain, access group `<TEAM>.dev.nvlab.sx`, synchronizable through iCloud Keychain (end-to-end encrypted by Apple). Only an app signed by that team with that entitlement can read them.
- **Broker**: Sx.app listens on a Unix socket in its app-group container. Every connection's code signature is checked via its audit token; only the `sx` binary signed by the same team (`identifier dev.nvlab.sx.cli`) is served. Other processes are refused.
- **Terminal approvals** (off until turned on with Touch ID): the macOS login password typed at a terminal approves listed requests; Sx.app verifies it and rate-limits attempts. Its strength is the password's: a process that can read your keystrokes can reuse it (see the warning above).
- **Approval**: Sx.app decides, not the CLI. Agent detection uses the caller's process ancestry, which an agent cannot rewrite (environment variables are a secondary signal).
- **Trust store**: `.sx.toml` approvals are keychain items on this Mac only — not files an agent could edit.
- **No network**: neither the app nor the CLI makes network calls. Bitwarden/1Password/plugin backends are their own tools.
- **Audit log**: `~/Library/Logs/sx-audit.jsonl` — who, which command, which names, outcome. Never values.

## Limits

- **A program that legitimately receives a secret can leak it.** If an agent edits your code to send `process.env` somewhere and then runs an allowed command, sx cannot see that. Give agents development keys with narrow scopes; tag production keys `prod`.
- **Masking covers stdout/stderr only**, not files or network traffic the program creates. Short values (< 4 bytes) are not masked.
- **macOS only.** No Linux, Windows or CI runners.
- **Not a team password manager.** Use Bitwarden or 1Password for shared secrets; sx can read from them.
- The Developer ID build is not sandboxed: the sandbox blocks code-signature checks of socket clients. An App Store build would need an XPC-based broker.

## Build from source

Requirements: Xcode 16+, [XcodeGen](https://github.com/yonaskolb/XcodeGen), an Apple Developer account signed in to Xcode.

```sh
make test       # unit tests (SwiftPM)
make install    # builds CLI + app, installs to /Applications, links ~/.local/bin/sx
make dmg        # signed installer
make release    # app notarized via the Xcode account; DMG via a notarytool profile (NOTARY_PROFILE)
```

Official builds are signed by team `37A7P47GPA`. For your own build, replace the team ID in `Sources/SxCore/Constants.swift` (`teamID`) and `App/project.yml` (`DEVELOPMENT_TEAM`, `application-groups`) and change the bundle IDs. Builds from different teams cannot read each other's secrets — that is the point.

Layout:

```
Sources/SxCore   shared: protocol, dotenv, redaction, policy, vault config, SSH keys
Sources/sx       CLI
App/Sources      Sx.app: broker, keychain store, approvals, SSH agent, UI
design/          icon and DMG art, rendered from code (make icons)
```

## License

[MIT](LICENSE) © 2026 Nazar Voitovych · [nvlab.co](https://nvlab.co) · security reports: see [SECURITY.md](SECURITY.md)
