# Thero Connect for Windows

## Requirements

- Windows Server 2016 or later, joined to the domain, as the client host.
- File servers on Windows Server 2012 R2 or later, or SharePoint Server 2016, 2019 or Subscription Edition farms (see [SharePoint Server](#sharepoint-server)).
- The Active Directory accounts of the Thero users in the same domain as the client host. Accounts of other domains of the forest and of other forests are not matched and get no access.
- A group managed service account (gMSA) for the service.
- Outbound TCP 443 to the link host that Thero names in the install command. A proxy must not inspect TLS for that host.
- For SharePoint roots, direct outbound HTTPS to every configured SharePoint host, without a proxy.

Group membership, identity mappings and share permissions take effect in Thero within 15 minutes. SharePoint limits are listed in [README.md](../README.md#sharepoint-server). NTFS permission edits take effect with the next walk that reaches the file (every 30 minutes, plus the duration of the walk).

## Service account rights

- NTFS and share read on every configured root (never Modify).
- Member of the local group "Power Users" on each file server, to read share permissions.
- Member of "Access Control Assistance Operators" on each file server, for remote access checks.
- Member of "Windows Authorization Access Group" in the domain.
- Inbound firewall rule "Netlogon Service Authz (RPC)" enabled on each file server.

`install` grants the account "Log on as a service".

## SharePoint Server

A client with `url` roots indexes SharePoint Server site collections instead of file shares (see [config.yaml](../README.md#configyaml)). On the farm:

- Give the gMSA a Full Read user policy on the Default zone of every web application that holds a configured site collection: Central Administration, Manage web applications, User Policy, Add Users, zone Default, account `DOMAIN\gmsa$`, permission Full Read. Full Read includes the permission to read role assignments; without it the root reports `denied` and has no readers.
- Register `HTTP/<host>` on the application pool account of the web application for every configured host, host-named site collections included, for example `setspn -S HTTP/intranet.corp.example CORP\sp-apppool`. When the service principal name differs from the host in `url`, set `spn` on the root.
- Enable Integrated Windows authentication with Negotiate (Kerberos) on the zone of `url`. The client uses Kerberos only and never falls back to NTLM, and it never delegates its credentials.
- Extended Protection on the IIS site of the web application must be Off or Allow, not Require. With Require every request is refused and the root is `unavailable`.
- A certificate from an internal certification authority must chain to a root in the Trusted Root Certification Authorities store of the local computer. The client has no option to trust other certificates or to skip the check.
- The client needs direct outbound HTTPS to every configured SharePoint host. It never uses a proxy for SharePoint and never follows a redirect.

The gMSA's membership in "Windows Authorization Access Group" lets the client read the current groups of each person. `check` prints `root <id> site` and `root <id> site users`; on failure it names the reason and the service principal name, for example a rejected Kerberos ticket, a redirect or an untrusted certificate. These details stay in the local log and are never sent to Thero.

## DFS namespaces

A root may be a domain based or standalone DFS namespace path. The client resolves namespace paths through the Windows DFS client and then reads every folder and file from the physical share it names.

- Every handle is checked against the physical path it names. When Windows serves a path from another server or share, for example because a folder turned into a DFS link during a walk, the open fails and the folder or file is reported as unavailable. This check applies to plain roots too.
- Link targets on Samba servers need the Linux client. On this client their access check fails and they get no readers.
- Set `DfsDnsConfig=1` on every Windows namespace server, so referrals carry fully qualified host names. Short names and IP addresses are skipped and the link stays incomplete.
- Before Thero Connect checks a target, the Windows DFS client has already connected to the target it picked, as the service account. Harden the Thero Connect host:
  - Restrict outgoing NTLM traffic to remote servers.
  - Disable LLMNR and NetBIOS over TCP/IP (NBT-NS).
  - Stop and disable the WebClient service.
  - Require SMB signing for the SMB client.

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
