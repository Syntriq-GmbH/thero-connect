# AGENTS.md

This file provides guidance to coding agents working in this repository.

## What this is

Thero Connect: a small Windows service that runs in a customer network and lets Thero index on-premises SMB file shares without opening any inbound port. It connects outbound to Thero over WebSocket with mutual TLS and answers a narrow set of read requests. Thero never receives a route into the network or a password. The server side lives in the `thero-ai` repository (`backend/python/app/connectors/sources/smb_share/`).

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
- Windows API calls live only in `*_windows.go`; everything else stays testable behind `source`.

## Git

- Branch names: English, at most 5 words.
- Commit messages: English, at most 5 words.
- PR descriptions: English, at most 30 words, factual, saying what changed.
- Name no tool that wrote a change in code, file names, branches, commits or PRs. No co-author or "generated with" lines.

## Commands

```bash
go vet ./...
go test ./...
GOOS=windows GOARCH=amd64 go vet ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o thero-connect.exe .
go test -tags e2e -run TestE2E -count=1 -timeout 0 .
```

## Layout

Everything is `package main` at the repository root.

- `main.go`: command dispatch, flags, the `check` command, `config.yaml` loading and validation, state paths, atomic file writes, logger setup.
- `link.go`: protocol structs, TLS, `enroll`, `serve` with the reconnect loop, one link session, certificate renewal.
- `ops.go`: the handlers `walk`, `principals`, `access` and `read`, walk state, class registry (`classes.json`), last complete walk per root (`walks.json`), daily quota (`quota.json`), rate limiter, read window.
- `source.go`: the `source` and `file` interfaces, portable types, sentinel errors and the pure helpers (paths, UNC, excludes, descriptors, classes, LDAP filter, account matching, error codes).
- `source_windows.go`: `windowsSource`, the only real `source`.
- `system_windows.go`: DPAPI, service, folder ACLs, install, uninstall, event log.
- `system_other.go`: development stand-ins of the system functions for other platforms; never released.
- `link_test.go`: `fakeSource` and in-process TLS link server tests.
- `ops_test.go`: handler tests on `fakeSource`.
- `source_test.go`: table tests of the pure helpers and security descriptor builders.
- `source_windows_test.go`: struct layout and DLL export tests, run on the Windows CI job.
- `protocol_test.go`: fixture round trip, protocol digest, chunk layout.
- `e2e_test.go`: real enrollment and link against a running thero-ai (`-tags e2e`).
- `protocol/v1/`: the canonical protocol.

## Protocol

`protocol/v1` (schema, fixtures, `chunk.bin`) is canonical. Change the schema, the fixtures, `protocolDigest` in `protocol_test.go` and the thero-ai copy `backend/python/tests/fixtures/smb_protocol_v1` with its `PROTOCOL_DIGEST` together. A breaking change creates `protocol/v2` and version 2.

## Testing

Portable logic runs on macOS and Linux through `fakeSource`. Windows code is vetted and built with `GOOS=windows`, and its layout tests run on the Windows CI job. Behaviour against a real domain follows the checklist in the README.
