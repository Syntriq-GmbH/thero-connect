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
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o thero-connect.exe ./cmd/thero-connect
```
