# Thero Connect

## What it does

Thero Connect is a Windows service in your network that lets Thero index Windows file shares and enforce their read permissions, without any inbound port. It dials out to Thero over WebSocket with mutual TLS 1.3 and answers four read requests that Thero drives. Thero never gets a route into the network and never holds an SMB or Active Directory password. Only this leaves the network: file metadata (path, size, times, a permission class) of the configured roots, the bytes of files Thero asks for, the Active Directory accounts whose email matches a Thero member's email, and the list of readers per permission class.

## Requirements

- Windows Server 2016 or later, joined to the domain, for the client host.
- File servers on Windows Server 2012 R2 or later.
- The Thero users' Active Directory accounts in the same domain as the client host. Accounts of other domains of the forest and of other forests are not matched and get no access.
- A group managed service account (gMSA) for the service.
- Outbound TCP 443 to the link host Thero names in the install command. A proxy must not inspect TLS for that host.

Access limits: group membership, identity mappings and share permissions take effect in Thero within 15 minutes. NTFS permission edits take effect with the next walk that reaches the file (every 30 minutes plus the duration of the walk).

## Service account rights

- NTFS and share read on every configured root (never Modify).
- Member of the local group "Power Users" on each file server, to read share permissions.
- Member of "Access Control Assistance Operators" on each file server, for remote access checks.
- Member of "Windows Authorization Access Group" in the domain.
- Inbound firewall rule "Netlogon Service Authz (RPC)" enabled on each file server.

`install` grants "Log on as a service".

## Install

1. Download `thero-connect.exe` and `thero-connect.exe.sha256` from the latest release and compare the checksum (`Get-FileHash thero-connect.exe`).
2. Copy the binary to `C:\Program Files\Thero Connect\`.
3. As administrator create `C:\ProgramData\Thero Connect` and write `config.yaml` there (see below).
4. In Thero open the connector settings, click "Create install command" and run the command as administrator within 15 minutes:
   ```
   thero-connect.exe enroll -url wss://<host> -ca <fingerprint> -token <token>
   ```
   It refuses a folder that another user owns and restricts the folder to SYSTEM and Administrators.
5. `thero-connect.exe install -account DOMAIN\gmsa$`
6. `thero-connect.exe check`

`enroll`, `run`, `install` and `check` take `-dir <folder>` to use another folder than `C:\ProgramData\Thero Connect`.

## config.yaml

```yaml
proxy: http://proxy.corp.example:3128
roots:
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

- `proxy`: optional HTTP proxy for the link; empty uses the `HTTPS_PROXY` and `NO_PROXY` environment variables.
- `roots`: 1 to 64 shares or share folders. `id` is lower case letters, digits, `_` and `-`, at most 32 characters, and is what Thero sees. `path` is a UNC path.
- `exclude`: patterns with `*`, `?` and `[...]`, matched case-insensitively against every name and every leading part of a relative path with `/` separators. A file below an excluded folder is never listed and never read.
- `limits`: for `max_file_mb`, `max_gb_per_day` and `max_mbit` 0 or a missing value means the default shown above. `read_window` is local time and may wrap midnight; empty allows reads at any time.

Only a local administrator may change `config.yaml`. Thero can only ask for configured root ids. Restart the service after a change.

## Limits and quotas

- Files above `max_file_mb`, paths over 1024 characters and names Windows reserves (device names such as `CON` or `aux.txt`, names ending in a dot or space) are not listed and not read.
- `max_gb_per_day` caps the bytes read per local day. A read reserves its full size before it starts and gives back only what it never sent, so canceled and failed reads count too; the counter survives restarts.
- `max_mbit` caps the read bandwidth of all reads together.
- At most two reads run at once; each sends at most 4 MiB before Thero confirms receipt.
- A read opens the file without write sharing: while someone has the file open for writing the read is refused as busy, and while it runs nobody can open the file for writing.
- Every folder on the way from the share to a file stays open without delete sharing until the file is open, and none of them may be a junction or symbolic link, so the path cannot be redirected outside the share in between.
- A root grants access only while its last complete walk started less than 6 hours ago. A failed root listing withdraws all access for that root until a walk completes again.

## Operations

- Logs: Event Viewer, Windows Logs, Application, source `TheroConnect`.
- The client certificate is valid for 30 days and renews itself when less than 10 days remain. An expired certificate needs a new enrollment.
- Revoking the machine in Thero disconnects it at once; reconnecting fails until it is enrolled again with a new install command.
- Enrolling again restricts the folder to SYSTEM and Administrators, so the service can no longer read it: run `uninstall` and `install` afterwards.
- `thero-connect.exe uninstall` stops and removes the service; the folder stays.

## Verify on a domain

Before the first rollout check on a real domain:

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

## Development

```bash
go vet ./...
go test ./...
GOOS=windows GOARCH=amd64 go vet ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o thero-connect.exe .
go test -tags e2e -run TestE2E -count=1 -timeout 0 .
```

`protocol/v1` holds the canonical protocol (JSON schema, fixtures, `chunk.bin`). thero-ai keeps a byte-identical copy; `TestDigest` pins it. A breaking change creates `protocol/v2`.

Release: push a tag `vX.Y.Z`. The release workflow tests, builds `thero-connect.exe` for Windows amd64 with the version from the tag and publishes it with its `.sha256` file as a GitHub release.
