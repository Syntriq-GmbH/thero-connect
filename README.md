# Thero Connect

Thero Connect is a small service in your network that lets Thero index SMB file shares and enforce their read permissions without any inbound port. It dials out to Thero over WebSocket with mutual TLS 1.3 and answers four read requests that Thero drives. Thero never gets a route into your network and never holds an SMB or Active Directory password.

Only this leaves the network:

- file metadata (path, size, times, a permission class) of the configured roots,
- the bytes of files Thero asks for,
- the Active Directory accounts whose email matches the email of a Thero member,
- the list of readers per permission class.

## Platforms

| Platform | Release file | Guide |
|---|---|---|
| Windows Server, amd64 | `thero-connect.exe` | [windows/README.md](windows/README.md) |
| Windows Server and Windows on ARM, arm64 | `thero-connect-arm64.exe` | [windows/README.md](windows/README.md) |
| Linux, amd64 | `thero-connect-linux-amd64` | [linux/README.md](linux/README.md) |
| Linux, arm64 | `thero-connect-linux-arm64` | [linux/README.md](linux/README.md) |

Every release file has a `.sha256` file next to it. Both clients speak the same protocol and read the same `config.yaml`. For a Windows file server they report the same readers, because there the file server decides every access check. The Linux client can also index shares on Samba servers in an Active Directory domain.

## config.yaml

The format is the same on every platform.

```yaml
proxy: http://proxy.corp.example:3128
principal: thero-connect@CORP.EXAMPLE
roots:
  - id: projects
    path: \\files.corp.example\projects
    server: samba
  - id: finance
    path: \\fs01.corp.example\finance
    exclude:
      - "~$*"
      - "*.tmp"
      - Archive/Old
limits:
  max_file_mb: 20
  max_gb_per_day: 50
  max_mbit: 40
  read_window: "19:00-07:00"
```

- `proxy`: optional HTTP proxy for the link. Without it the client uses the `HTTPS_PROXY` and `NO_PROXY` environment variables.
- `principal`: Linux only, and required there. The service account as `name@REALM` with the realm in upper case. The Windows client refuses it.
- `roots`: 1 to 64 shares or share folders.
  - `id`: lower case letters, digits, `_` and `-`, at most 32 characters. This is the name Thero sees.
  - `path`: a UNC path. The Linux client needs the server's fully qualified name.
  - `server`: `windows` (the default) lets the file server decide every access check. `samba` is Linux only: the client computes access from the directory and the file's permissions, and setting it confirms the [Samba prerequisites](linux/README.md#samba-prerequisites). One server cannot have roots of both kinds. The Windows client refuses `samba`.
  - `exclude`: patterns with `*`, `?` and `[...]`, matched case-insensitively against every name and every leading part of the relative path (with `/` separators). A file below an excluded folder is never listed and never read.
- `limits`: `max_file_mb`, `max_gb_per_day` and `max_mbit` use the values shown above when they are 0 or missing. `read_window` is local time as `HH:MM-HH:MM` and may wrap midnight; without it reads are allowed at any time.

Only a local administrator (root on Linux) may change `config.yaml`. Thero can only ask for configured root ids. Restart the service after a change.

## Limits

- Files above `max_file_mb`, paths over 1024 characters and names Windows reserves (device names such as `CON` or `aux.txt`, names ending in a dot or space) are neither listed nor read.
- `max_gb_per_day` caps the bytes read per local day. A read reserves its full size before it starts and gives back only what it never sent, so canceled and failed reads count too. The counter survives restarts.
- `max_mbit` caps the bandwidth of all reads together.
- At most two reads run at once. Each sends at most 4 MiB before Thero confirms receipt.
- A read opens the file without write sharing. While someone has the file open for writing, the read is refused as busy; while the read runs, nobody can open the file for writing.
- Every folder between the share and a file stays open without delete sharing until the file is open, and none of them may be a junction or symbolic link, so the path cannot be redirected outside the share in between.
- A root grants access only while its last complete walk started less than 6 hours ago. A failed root listing withdraws all access for that root until a walk completes again.
- A share permission entry for OWNER RIGHTS that is not inherit-only gives the root no readers.
- When a permission, path or identity cannot be determined exactly, the client grants nothing. Samba roots only ever report fewer readers than Samba would allow; [linux/README.md](linux/README.md#limits) lists the cases.

## Protocol

`protocol/v1` holds the protocol: a JSON schema, fixtures and `chunk.bin`. The Thero server keeps a byte-identical copy, and `TestDigest` in `core/protocol_test.go` pins it. A breaking change creates `protocol/v2`. The `enroll` and `hello` messages name the client version and platform, for example `1.4.0 linux/arm64`.

## Build and test

Requires the Go version named in `go.mod`.

```bash
go vet ./...
go test ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o thero-connect.exe ./windows
GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -o thero-connect-arm64.exe ./windows
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o thero-connect-linux-amd64 ./linux
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o thero-connect-linux-arm64 ./linux
```

`core/` holds the shared client: configuration, commands, link, request handlers and the permission logic. `windows/` and `linux/` each hold the file share access and system integration of one operating system. `test/samba/` is a Samba Active Directory lab in Docker that checks the Linux client against real SMB opens. [AGENTS.md](AGENTS.md) has the full command list and the contribution rules.

Releases: pushing a tag `vX.Y.Z` runs the release workflow. It tests, builds the four files of the platform table with the version from the tag and publishes them with their `.sha256` files as one GitHub release.
