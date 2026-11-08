# AGENTS.md

Guide for every contributor and coding agent in this repository. Its code doctrine, git rules and commands apply to every change.

## What this is

Thero Connect: small clients, one per platform (Windows, Linux) on a shared core, that run in a customer network and let Thero index on-premises SMB file shares and SharePoint Server site collections without opening any inbound port. Each client connects outbound to Thero over WebSocket with mutual TLS and answers a narrow set of read requests. Thero never receives a route into the network or a password. The server side lives in the private `thero-ai` repository (`backend/python/app/connectors/sources/smb_share/`).

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
- The SharePoint decision lives only in `core`: `siteAccess`, the verified site user row (login and `UserId.NameId` equal to the person's login and SID), claim matching, the masks and the one need `0x31021`, the version rule, the owner rule for read only own items, the scope chain, `MemberOf`, `InDomain` and `KerberosToken`. A platform only supplies `Members` (LDAP values) and `Negotiate` (a Kerberos token for one request, never with delegation), and both platforms pass every token through `core.KerberosToken`.
- Every SharePoint request goes through the one request function in `core/sharepoint.go`, and its allow list is checked on the built request right before it is sent: the configured host only, `GET` only below `<web>/_api/` of the site collection or of a web a walk found, `POST` only to `<site>/_api/contextinfo` and `<site>/_api/site/getchanges`. URLs are built with `net/url`, path segments are escaped one by one, request bodies come from `json.Marshal`, and absolute URLs from responses are never requested. No `X-HTTP-Method`, no `$batch`, no SOAP, no proxy, no redirects, no cookies.
- Decoding is strict for every SharePoint field that decides access or the version rule: it is decoded into a pointer or a type that records presence, and a missing or unparsable value is never read as `false` or `0`. Missing on a web or list makes it `incomplete`, on a row the row gets `class: null`, on a role assignment the scope grants nothing, on a user row the row is not verified. 64-bit values are accepted as JSON strings or numbers.
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
SMB_E2E_URL=wss://<host> SMB_E2E_CA=<fingerprint> SMB_E2E_TOKEN=<token> SMB_E2E_ALICE=<email> SMB_E2E_BOB=<email> go test -tags e2e -run '^TestE2E$' -count=1 -timeout 0 ./core
SMB_E2E_URL=wss://<host> SMB_E2E_CA=<fingerprint> SMB_E2E_TOKEN=<token> SMB_E2E_ALICE=<email> SMB_E2E_BOB=<email> SP_E2E_PORT=<port> go test -tags e2e -run '^TestE2ESharePoint$' -count=1 -timeout 0 ./core
test/samba/run.sh up && test/samba/run.sh fresh && test/samba/run.sh truth && test/samba/run.sh test && test/samba/run.sh idmap
test/samba/run.sh down
```

`TestE2E` enrolls against a running Thero server and keeps the link for `SMB_E2E_SECONDS` (default 900); without `SMB_E2E_URL` it skips. `TestE2ESharePoint` does the same with one URL root `intranet` on the fake farm of `core/sharepoint_test.go`, served on `127.0.0.1:<SP_E2E_PORT>` (a random port without it); the farm takes `POST /_control/<step>` with the steps `delete-handbook`, `alice-only-handbook` and `draft-on-top`. `SMB_E2E_ALICE` and `SMB_E2E_BOB` are the emails of the two test people. `run.sh up` also registers `HTTP/localhost` on the lab service account and exports `test/samba/out/http.keytab`; `run.sh test` runs `TestSamba`, `TestSambaNegotiate` and `TestSambaMembers` with `-race`. `run.sh idmap` leaves the file server with a cut idmap range; run `up` again before another `test`. One lab runs per Docker project: set `THERO_SMB_PROJECT` (default `thero-smb`) and `THERO_SMB_NET`, the first three octets of a free /24 (default `172.30.53`), to run a second lab or to avoid an overlapping network.

## Layout

One module, a shared `core` package and one `package main` folder per platform.

- `core/main.go`: `Platform` (what a platform supplies), `Main`, command dispatch, flags, the `check` command (also for URL roots), `config.yaml` loading and validation (`path` or `url` roots, `spn`), state paths, atomic file writes, logger setup.
- `core/link.go`: protocol structs, TLS, `enroll`, `serve` with the reconnect loop, one link session, certificate renewal.
- `core/ops.go`: the handlers `walk`, `principals`, `access` and `read`, walk state, class registry (`classes.json`), last complete walk per root (`walks.json`), daily quota (`quota.json`), rate limiter, read window. URL roots branch to `siteWalk`, `siteAccess` and `sites.open`.
- `core/sharepoint.go`: everything specific to SharePoint Server: the HTTP client and the one request function with its allow list, form digest, full and incremental walk with the in-memory baseline, scopes, version rule, Markdown of list items, links, class ids, the access snapshot, claim matching, masks, the `GetUserEffectivePermissions` cache and reads.
- `core/sharepoint_test.go`: the fake farm on `httptest` TLS and every SharePoint core test, including the full cycle offline (`TestSharePointCycle`).
- `core/source.go`: the `Source` and `File` interfaces, portable types, sentinel errors and the pure helpers (paths, UNC, SIDs, FILETIME, accounts from directory values, `Member`, `MemberOf`, `InDomain`, `KerberosToken`, excludes, descriptors, classes, LDAP filter, account matching, error codes).
- `core/link_test.go`: `TestMain` with a plain `Platform`, `fakeSource` and in-process TLS link server tests.
- `core/ops_test.go`: handler tests on `fakeSource`.
- `core/source_test.go`: table tests of the pure helpers, golden class ids and security descriptor builders.
- `core/protocol_test.go`: fixture round trip, protocol digest, chunk layout.
- `core/e2e_test.go`: real enrollment and link against a running Thero server (`-tags e2e`), for a file share (`TestE2E`) and for the fake farm (`TestE2ESharePoint`).
- `windows/main.go`: `main`, DPAPI, service, folder ACLs, install, uninstall, event log.
- `windows/source.go`: `windowsSource`, the Windows `Source`, including `Members` over LDAP and `Negotiate` through SSPI limited to Kerberos.
- `windows/source_test.go`: struct layout, DLL export and share tests, run on the Windows CI jobs.
- `windows/README.md`: Windows requirements, rights, SharePoint Server, install, operations.
- `linux/main.go`: `main`, folder ownership and modes, install, uninstall, the systemd unit.
- `linux/source.go`: the Linux `Source`: Kerberos login, `Negotiate` for SharePoint, SMB file plane, share descriptors over srvsvc, MS-RAA for Windows file servers, the token and `core.Grants` for Samba file servers.
- `linux/directory.go`: domain controller lookup, LDAP with a sealed GSSAPI bind, accounts, `Members`, own SID and token facts.
- `linux/main_test.go`, `linux/source_test.go`: unit tests that run on macOS and Linux.
- `linux/samba_test.go`: access matrix, Kerberos to a local HTTPS server and `Members` against the Samba lab (`-tags samba`, driven by `test/samba/run.sh`).
- `linux/README.md`: Linux requirements, keytab, rights, SharePoint Server, Samba prerequisites, install, operations, limits.
- `test/samba/`: Samba Active Directory lab in Docker (`compose.yaml`, `run.sh`). Its passwords are lab values only.
- `protocol/v1/`: the canonical protocol.

## Protocol

`protocol/v1` (schema, fixtures, `chunk.bin`) is canonical. Change the schema, the fixtures, `protocolDigest` in `core/protocol_test.go` and the server copy `backend/python/tests/fixtures/smb_protocol_v1` in `thero-ai` with its `PROTOCOL_DIGEST` together. A breaking change creates `protocol/v2` and version 2.

## Testing

Portable logic in `core` runs on macOS and Linux through `fakeSource`; SharePoint logic runs against the fake farm, which logs every request and fails a test when one is not an allowed `GET` or `POST`. Windows code is vetted and built with `GOOS=windows` for amd64 and arm64, and its tests run on the Windows CI jobs (`windows-latest`, `windows-11-arm`). Linux unit tests run on macOS and in the ubuntu CI job, which also builds both Linux architectures and checks `gofmt`. The Samba lab runs locally; it is not part of CI. Releases ship `thero-connect.exe` (amd64), `thero-connect-arm64.exe` (arm64 Windows Server and Windows on ARM), `thero-connect-linux-amd64` and `thero-connect-linux-arm64`, each with a `.sha256` file.

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

### SharePoint farm checklist

Before the first SharePoint rollout, on SharePoint Server 2016, 2019 and Subscription Edition, with the Windows and the Linux client:

- The readers of every class equal a real browser open as Alice and as Bob for web, list, folder and item scopes, SharePoint groups, AD group claims, nested AD groups, Everyone, a site collection administrator, a Deny policy, Limited Access, View Only, read only own items, approval, minor versions and a checked out file.
- The Windows and the Linux client report the same readers.
- No row in `UserInfo` or `siteuserinfolist` changes during a full cycle, including the very first contact of the service account with a site collection: same row count, same `tp_ExternalToken*` and `Modified` values.
- The IIS logs show only the allowed methods and paths.
- The results of L13 to L16 are recorded in `README.md`.

Lab checks. Each has a default that can only remove readers; a result that disagrees changes the code only in that direction.

- L1: `getusereffectivepermissions` works over `GET`, and the whole cycle writes nothing (row count, `tp_ExternalToken*` and `Modified` of UserInfo unchanged, the first contact included). If `GET` is refused nobody is a reader. If anything is written, SharePoint roots stop until an owner decision is recorded in `README.md`.
- L2: SharePoint's answer applies web application Deny policies. If not, deny policies must be read separately before rollout, and a deny that cannot be resolved gives the web application no readers.
- L3: SharePoint's answer includes AD group claims, site collection administrators and Everyone. Under-reporting only removes readers; record it.
- L4: `HasUniqueRoleAssignments` in `$select` of items in lists over 5,000 rows works without a threshold error. Lists that fail are `incomplete`.
- L5: `OData__UIVersion`, `OData__Level` and `OData__ModerationStatus` are selectable, and with draft visibility limited to editors the Full Read account sees the published version in the row and in `$value`. Missing fields give `class: null`.
- L6: `ReadSecurity` is selectable on 2016. Without it every generic list is treated as read only own items.
- L7: change log items carry `ListId`; item, folder, list and web inheritance breaks and folder renames appear; an expired token gives an error; tokens have scope `1`. If security changes are missing, the 30 minute full walk is the bound.
- L8: `odata=nometadata` and `$skiptoken=Paged=TRUE%26p_ID=` work on 2016. Failure makes lists `incomplete`.
- L9: Kerberos with one service principal name per host, host-named site collections, the gMSA through SSPI limited to Kerberos, and Extended Protection `Require` failing with the documented local message.
- L10: throughput of `getusereffectivepermissions` (about 90 calls per second in steady state) and walk timings. If the farm cannot carry it, only the parallelism is lowered.
- L11: `X-FORMS_BASED_AUTH_ACCEPTED: f` gives a status instead of a redirect. Either way the root is `unavailable`.
- L12: Full Read reads `siteusers` with `UserId`, role assignments and SharePoint group members. A `403` gives `denied` and no readers.
- L13: `UserId.NameId` of a Windows user row is the user's SID, and `siteusers` returns every row without paging. If not, no row is verified and nobody is a reader; rows beyond a page are not verified.
- L14: `GetUserEffectivePermissions` honours the restricted permission set of the web application. If not, that web application gets no readers.
- L15: whether `$value` downloads create audit or usage analytics entries. Record the result in `README.md`.
- L16: `$expand=AttachmentFiles` together with `p_ID` paging works on 2016. If not, generic lists are `incomplete`.
- L17: `GetFileById(...)/$value` answers with the same `ETag` as the file's `ETag` property and refuses a stale `If-Match` with `412`. A missing or different `ETag` makes every library read `changed`; a farm that ignores `If-Match` is still covered by the client's own comparison.
