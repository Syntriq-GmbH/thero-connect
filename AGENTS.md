# AGENTS.md

Guide for every contributor and coding agent in this repository. Its code doctrine, git rules and commands apply to every change.

## What this is

Thero Connect for file shares: small clients, one per platform (Windows, Linux) on a shared core, that run in a customer network and let Thero index on-premises SMB file shares without opening any inbound port. Each client connects outbound to Thero over WebSocket with mutual TLS and answers a narrow set of read requests. Thero never receives a route into the network or a password. The server side lives in the private `thero-ai` repository (`backend/python/app/connectors/sources/smb_share/`).

## Code doctrine: simple and minimal

Top priority for every change. It outranks elegance, extensibility and completeness:

- **Minimal.** The smallest solution that meets the requirement. No abstraction, no interface, no helper, no option "for later". No code for cases nobody asked for.
- **Few files.** What belongs together stays in one file. Split only when a file really becomes unreadable or a part is needed elsewhere, not preemptively by layer.
- **Flat instead of nested.** Return early, no deep condition trees, no indirection across several levels. Whoever reads the code should see the flow in one piece.
- **No comments.** Names and structure explain the code.
- **Readable before clever.** Spelled-out names, straightforward control flow, no dense one-liners, no reflection tricks.
- **Add nothing that is not needed.** No extra configuration, no new package, no new dependency without a consumer in the same commit.
- **Standard library first.** `CGO_ENABLED=0`; Windows APIs through `golang.org/x/sys/windows`.
- **Fail closed.** When a permission, path or identity cannot be determined exactly, the client returns an error and grants nothing.
- `core` imports no platform package and has no build-tagged file.
- Every file in `windows/` starts with `//go:build windows`; `golang.org/x/sys/windows` appears only there.
- Every file in `linux/` starts with `//go:build !windows` (`samba_test.go`: `//go:build samba`), not `linux`, so its pure tests run on macOS too; releases build it with `GOOS=linux` only. SMB, RPC, LDAP and systemd code appears only there.
- The permission decision (`supported`, `classOf`, `Grants`, `DeniedSIDs`, the share-then-file order, the OWNER RIGHTS share refusal, the descriptor id check, the account-enabled rule in `AccountOf`) lives only in `core`. A platform folder only gathers facts (bytes, ids, tokens) or asks the file server.
- The Linux client authenticates with Kerberos from its keytab only. No NTLM credential or mechanism is ever registered, and the global credential and mechanism stores of go-msrpc are never used.
- Every bump of `go-smb2/v2`, `go-msrpc` or `go-smb2.fork` gets a diff review and the full Samba lab run before it merges.

## Git

- Branch names: English, at most 5 words.
- Commit messages: English, at most 5 words.
- PR descriptions: English, at most 30 words, factual, saying what changed.
- Name no tool that wrote a change in code, file names, branches, commits or PRs. No co-author or "generated with" lines.

## Commands

```bash
gofmt -l .
go vet ./...
go test ./...
GOOS=windows GOARCH=amd64 go vet ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o thero-connect.exe ./windows
GOOS=windows GOARCH=arm64 go vet ./...
GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -o thero-connect-arm64.exe ./windows
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o thero-connect-linux-amd64 ./linux
GOOS=linux GOARCH=arm64 go vet ./...
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o thero-connect-linux-arm64 ./linux
go vet -tags e2e ./...
go vet -tags samba ./...
GOOS=windows GOARCH=amd64 go vet -tags dfs ./windows
SMB_E2E_URL=wss://<host> SMB_E2E_CA=<fingerprint> SMB_E2E_TOKEN=<token> go test -tags e2e -run TestE2E -count=1 -timeout 0 ./core
test/samba/run.sh up && test/samba/run.sh fresh && test/samba/run.sh truth && test/samba/run.sh test && test/samba/run.sh dfs && test/samba/run.sh idmap
test/samba/run.sh stop fs2 && test/samba/run.sh start fs2
test/samba/run.sh down
```

`TestE2E` enrolls against a running Thero server and keeps the link for `SMB_E2E_SECONDS` (default 900); without `SMB_E2E_URL` it skips. `run.sh idmap` leaves the file server with a cut idmap range; run `up` again before another `test`. `run.sh dfs` runs `TestSambaDFS` against the namespace shares `ns` and `ns2` and the domain namespace `corp`. `run.sh stop <service>` and `run.sh start <service>` stop and start one lab container, for example `fs2` to take a link target down. One lab runs per Docker project: set `THERO_SMB_PROJECT` (default `thero-smb`) and `THERO_SMB_NET`, the first three octets of a free /24 (default `172.30.53`), to run a second lab or to avoid an overlapping network.

## Layout

One module, a shared `core` package and one `package main` folder per platform.

- `core/main.go`: `Platform` (what a platform supplies), `Main`, command dispatch, flags, the `check` command, `config.yaml` loading and validation, state paths, atomic file writes, logger setup.
- `core/link.go`: protocol structs, TLS, `enroll`, `serve` with the reconnect loop, one link session, certificate renewal.
- `core/ops.go`: the handlers `walk`, `principals`, `access` and `read`, walk state, DFS resolution (`locate`, `physical`), class registry (`classes.json`), last complete walk per root (`walks.json`), link targets of the last complete walk (`mounts.json`), daily quota (`quota.json`), rate limiter, read window.
- `core/source.go`: the `Source` and `File` interfaces, portable types, sentinel errors and the pure helpers (paths, UNC, SIDs, FILETIME, accounts from directory values, excludes, descriptors, classes, LDAP filter, account matching, error codes).
- `core/link_test.go`: `TestMain` with a plain `Platform`, `fakeSource` and in-process TLS link server tests.
- `core/ops_test.go`: handler tests on `fakeSource`, including the DFS walk, access and read tests (`TestWalk*`, `TestAccessPerTarget`, `TestReadThroughMounts`, `TestStateMountsAndTargets`).
- `core/source_test.go`: table tests of the pure helpers, golden class ids and security descriptor builders.
- `core/protocol_test.go`: fixture round trip, protocol digest, chunk layout.
- `core/e2e_test.go`: real enrollment and link against a running Thero server (`-tags e2e`).
- `windows/main.go`: `main`, DPAPI, service, folder ACLs, install, uninstall, event log.
- `windows/source.go`: `windowsSource`, the Windows `Source`.
- `windows/source_test.go`: struct layout, DLL export, share, physical-name guard, link detection and referral mapping tests, run on the Windows CI jobs.
- `windows/dfs_test.go`: `TestDfsNamespace` against a standalone namespace on the runner (`-tags dfs`, CI job `windows-dfs`).
- `windows/README.md`: Windows requirements, rights, install, operations.
- `linux/main.go`: `main`, folder ownership and modes, install, uninstall, the systemd unit.
- `linux/source.go`: the Linux `Source`: Kerberos login, SMB file plane, DFS referrals, share descriptors over srvsvc, MS-RAA for Windows file servers, the token and `core.Grants` for Samba file servers.
- `linux/directory.go`: domain controller lookup, LDAP with a sealed GSSAPI bind, accounts, own SID and token facts.
- `linux/main_test.go`, `linux/source_test.go`: unit tests that run on macOS and Linux.
- `linux/samba_test.go`: access matrix (`TestSamba`) and DFS referrals and readers (`TestSambaDFS`) against the Samba lab (`-tags samba`, driven by `test/samba/run.sh`).
- `linux/README.md`: Linux requirements, keytab, rights, Samba prerequisites, install, operations, limits.
- `test/samba/`: Samba Active Directory lab in Docker (`compose.yaml`, `run.sh`) with two file servers and DFS namespaces. Its passwords are lab values only.
- `protocol/v1/`: the canonical protocol.

## Protocol

`protocol/v1` (schema, fixtures, `chunk.bin`) is canonical. Change the schema, the fixtures, `protocolDigest` in `core/protocol_test.go` and the server copy `backend/python/tests/fixtures/smb_protocol_v1` in `thero-ai` with its `PROTOCOL_DIGEST` together. A breaking change creates `protocol/v2` and version 2.

## Testing

Portable logic in `core` runs on macOS and Linux through `fakeSource`. Windows code is vetted and built with `GOOS=windows` for amd64 and arm64, and its tests run on the Windows CI jobs (`windows-latest`, `windows-11-arm`). The `windows-dfs` job installs the DFS Namespaces feature on `windows-latest`, creates a standalone namespace with two links and runs `go test -tags dfs -run Dfs ./windows`. Linux unit tests run on macOS and in the ubuntu CI job, which also builds both Linux architectures and checks `gofmt`. The Samba lab runs locally; it is not part of CI. Releases ship `thero-connect.exe` (amd64), `thero-connect-arm64.exe` (arm64 Windows Server and Windows on ARM), `thero-connect-linux-amd64` and `thero-connect-linux-arm64`, each with a `.sha256` file.

## Domain checklists

Before the first rollout of a release on a real domain, check the following.

Windows client:

- Power Users can read share information level 502.
- The remote access check result equals a real SMB open as Alice and as Bob for: share allow and deny, NTFS allow and deny order, inheritance, an empty DACL, nested groups, domain-local and server-local groups.
- Unsupported ACEs and ACEs with generic access bits make a file `class: null`.
- A deny ACE for "This Organization" and for "NTLM Authentication" gives `class: null`.
- A user with `sIDHistory` is evaluated correctly.
- A file with an allow ACE for INTERACTIVE gives `class: null`.
- A share descriptor without owner is evaluated.
- `SetSecurityInfo` on a file changes its change time as seen over SMB.
- An expired account is reported disabled.
- `LDAP_OPT_SIGN` and `LDAP_OPT_ENCRYPT` set to 1 work against the domain controllers.
- After `enroll`, `icacls` shows only SYSTEM and Administrators on the folder and on `state`.
- `enroll` refuses a folder created by a non-administrator.
- The service starts under the gMSA.
- Reading the descriptor (READ_CONTROL) works while a file is held open with deny-all sharing.

DFS namespaces, with both clients:

- The readers of every file in a namespace equal a real SMB open of the same file on its physical target, never the union of two targets.
- Two links to the same share index it once, and the same link wins on every walk.
- A link whose targets are all down is reported incomplete, and its records keep no readers.
- A domain based root walks, and the client never connects to the domain name itself.
- With `DfsDnsConfig=1`, referrals carry fully qualified names; with `DfsDnsConfig=0`, links are reported incomplete.

Linux client:

- The Windows checklist above passes with the Linux client.
- With the Windows and the Linux client enrolled on the same connector and roots, every permission class has the same readers.
- The LDAP bind works with "LDAP server signing requirements" set to "Require signing".
- Walk and read work on a share that requires encryption with AES-256-GCM.
- A Windows root configured with `server: samba` reports `unavailable` and no readers.
- On a Samba root, the readers match a real SMB open as Alice and as Bob for: share allow and deny, file allow and deny, inheritance, nested groups, domain-local groups and a disabled user.
- `enroll` refuses a folder that a non-root user created.
- After `install`, `stat` shows the owners and modes from the table in `linux/README.md`, `systemd-analyze verify` passes and `systemd-analyze security thero-connect` shows an exposure of 3.0 or less with no UNSAFE line.
- The service comes back 60 seconds after `kill -9`.
- `journalctl -u thero-connect` contains no keytab, ticket, file content or token data.
