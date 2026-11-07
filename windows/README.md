# Thero Connect for Windows

## Requirements

- Windows Server 2016 or later, joined to the domain, as the client host.
- File servers on Windows Server 2012 R2 or later.
- The Active Directory accounts of the Thero users in the same domain as the client host. Accounts of other domains of the forest and of other forests are not matched and get no access.
- A group managed service account (gMSA) for the service.
- Outbound TCP 443 to the link host that Thero names in the install command. A proxy must not inspect TLS for that host.

Group membership, identity mappings and share permissions take effect in Thero within 15 minutes. NTFS permission edits take effect with the next walk that reaches the file (every 30 minutes, plus the duration of the walk).

## Service account rights

- NTFS and share read on every configured root (never Modify).
- Member of the local group "Power Users" on each file server, to read share permissions.
- Member of "Access Control Assistance Operators" on each file server, for remote access checks.
- Member of "Windows Authorization Access Group" in the domain.
- Inbound firewall rule "Netlogon Service Authz (RPC)" enabled on each file server.

`install` grants the account "Log on as a service".

## Install

1. Download `thero-connect.exe` and `thero-connect.exe.sha256` from the latest release and compare the checksum with `Get-FileHash thero-connect.exe`. On arm64 take `thero-connect-arm64.exe` and its `.sha256` file instead and save the binary as `thero-connect.exe`.
2. Copy the binary to `C:\Program Files\Thero Connect\`.
3. As administrator create `C:\ProgramData\Thero Connect` and write `config.yaml` there (see [config.yaml](../README.md#configyaml)).
4. In Thero open the connector settings, click "Create install command" and run the command in an administrator PowerShell within 15 minutes. Leave out `-token` and paste the token when asked, so that it never appears in the process list or the command history:
   ```
   & 'C:\Program Files\Thero Connect\thero-connect.exe' enroll -url wss://<host> -ca <fingerprint>
   ```
   It refuses a folder, `config.yaml` or `state` folder not owned by Administrators or SYSTEM, and restricts the folder to SYSTEM and Administrators.
5. `& 'C:\Program Files\Thero Connect\thero-connect.exe' install -account 'DOMAIN\gmsa$'`
   This grants the account read access to the folder and write access to `state`, registers the event log source and the service `TheroConnect` (automatic, delayed start, restart after one minute) and starts it.
6. `& 'C:\Program Files\Thero Connect\thero-connect.exe' check`

`enroll`, `run`, `install` and `check` take `-dir <folder>` to use a folder other than `C:\ProgramData\Thero Connect`.

## Operations

- Logs: Event Viewer, Windows Logs, Application, source `TheroConnect`.
- The client key is stored with DPAPI for the local machine.
- The client certificate is valid for 30 days and renews itself when less than 10 days remain. An expired certificate needs a new enrollment.
- Revoking the machine in Thero disconnects it at once. Reconnecting fails until it is enrolled again with a new install command.
- Enrolling again restricts the folder to SYSTEM and Administrators, so the service can no longer read it. Run `uninstall` and `install` afterwards.
- `& 'C:\Program Files\Thero Connect\thero-connect.exe' uninstall` stops and removes the service. The folder stays.

## Build

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o thero-connect.exe ./windows
GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -o thero-connect-arm64.exe ./windows
```
