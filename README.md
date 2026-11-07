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
samba_servers:
  - fs03.corp.example
roots:
  - id: projects
    path: \\files.corp.example\projects
    server: samba
  - id: departments
    path: \\corp.example\departments
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
- `samba_servers`: Linux only, optional. Fully qualified names of Samba servers that are [DFS link targets](#dfs-namespaces) but host no root. Their shares are evaluated like roots with `server: samba`, with the same prerequisites. A host listed here must not have roots with `server: windows`. A Samba target missing from this list gets no readers. The Windows client refuses this key.
- `roots`: 1 to 64 shares, share folders or [DFS namespace](#dfs-namespaces) paths.
  - `id`: lower case letters, digits, `_` and `-`, at most 32 characters. This is the name Thero sees.
  - `path`: a UNC path. The Linux client needs the server's fully qualified name.
  - `server`: `windows` (the default) lets the file server decide every access check. `samba` is Linux only: the client computes access from the directory and the file's permissions, and setting it confirms the [Samba prerequisites](linux/README.md#samba-prerequisites). One server cannot have roots of both kinds. The Windows client refuses `samba`.
  - `exclude`: patterns with `*`, `?` and `[...]`, matched case-insensitively against every name and every leading part of the relative path (with `/` separators). A file below an excluded folder is never listed and never read.
- `limits`: `max_file_mb`, `max_gb_per_day` and `max_mbit` use the values shown above when they are 0 or missing. `read_window` is local time as `HH:MM-HH:MM` and may wrap midnight; without it reads are allowed at any time.

Only a local administrator (root on Linux) may change `config.yaml`. Thero can only ask for configured root ids. Restart the service after a change.

## DFS namespaces

A root may be a domain based (`\\corp.example\departments`) or standalone (`\\fs01.corp.example\departments`) DFS namespace path, or a folder below one. Links anywhere below the root are followed.

- Every folder and file is listed, read and checked against the physical share a link points to, with that share's own share and file permissions. Namespace permissions, link permissions and access-based enumeration grant nothing. Files stored in the namespace root share itself are checked against that share.
- Paths stay relative to the root, so a record keeps its path when a link moves to another target.
- Each link uses one target per walk. The client takes the targets in the order the namespace server sends them, sorts the targets of equal priority by name and keeps the target it used last as long as the server still offers it. It moves to the next target only when a target is unavailable or the share does not exist; when the service account is denied, the link stays incomplete. A link whose referral fails or whose targets all fail is reported incomplete and its records keep no readers until a later walk reaches a target. When a link switches to another target, Thero re-creates that link's records, because they now carry the other share's permissions.
- A link whose target lies inside, above or at the target of the root or of another link of the same root is skipped, so no folder is indexed twice in one root. Of two such links, the first in walk order wins.
- Referrals are asked again on every walk. Reads use the targets of the last complete walk. After a root's path changes, that root has no readers and serves no reads until its next complete walk. After an upgrade from a version without DFS support, a plain root keeps its readers, while a root that is a namespace path has no readers until its next complete walk.
- The service account needs Read on every DFS folder. A link hidden from it by access-based enumeration is not listed, and its records are deleted.
- Windows namespace servers need `DfsDnsConfig=1`, so referrals carry fully qualified host names. Targets with short names or IP addresses are skipped on both clients and the link ends incomplete.
- A root holds at most 10,000 links; links past that end incomplete.
- Samba link targets need the Linux client; list them in `samba_servers` unless they host a root. The [Linux](linux/README.md#dfs-namespaces) and [Windows](windows/README.md#dfs-namespaces) guides have the platform details.

Who controls scope: whoever can edit the namespace decides which shares the service account copies into Thero. A link can point at any share the service account can read, and its files are indexed with that share's real permissions. This is a decision about consent and about which data leaves the network, not a leak of readers, so restrict who may edit the namespace accordingly.

Stale targets: a link that still names a retired host sends Thero Connect to whoever registers that name again, and that host's content is indexed under the link. Remove dead links and targets from the namespace.

Access cost: one rights cycle checks every Thero member against every target share, so its cost grows with users times target shares. A namespace with one share per person, such as home folders for 1,000 people, does not finish a rights cycle, and its readers lapse. The `targets` field of the `walk complete` log line counts the physical shares a root reaches; keep it small for large organizations.

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
