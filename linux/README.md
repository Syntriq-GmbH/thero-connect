# Thero Connect for Linux

## Requirements

- Linux on amd64 or arm64 with systemd 247 or later (Ubuntu 22.04, Debian 12, RHEL 9 or later). The host does not need to join the domain.
- DNS that resolves the Active Directory zone, including `_ldap._tcp.dc._msdcs.<domain>`. On hosts with systemd-resolved the AD DNS servers must be the uplink of `127.0.0.53`, or `/etc/resolv.conf` must point at them.
- A clock within 5 minutes of the domain controllers, for example chrony synced from them.
- A dedicated domain user account for the service with AES keys, and its keytab (see below).
- The Kerberos realm is the upper case DNS domain (`corp.example` and `CORP.EXAMPLE`). Thero users and file servers are in that domain; other domains and forests are not supported.
- File servers named by their fully qualified name in every root (`\\fs01.corp.example\finance`). Short names, aliases and IP addresses are refused.
- Outbound TCP 443 to the link host that Thero names in the install command. A proxy must not inspect TLS for that host.
- From the host to the domain: TCP 88 (Kerberos) and 389 (LDAP) to the domain controllers, TCP 445 to every file server, and for Windows file servers TCP 135 plus the dynamic RPC ports. For SharePoint roots TCP 443 to every configured SharePoint host instead of the file server ports.

Authentication is Kerberos with the keytab only. There is no NTLM fallback. SMB signing is always required; SMB encryption is used when the file server requires it.

## config.yaml

The format is shared with Windows (see [config.yaml](../README.md#configyaml)). Linux needs `principal`, and roots on Samba servers need `server: samba`:

```yaml
principal: thero-connect@CORP.EXAMPLE
roots:
  - id: finance
    path: \\fs01.corp.example\finance
  - id: projects
    path: \\files.corp.example\projects
    server: samba
```

- `principal`: the service account as `name@REALM`, realm in upper case.
- `server`: `windows` (the default) lets the Windows file server decide every access check, exactly as the Windows client does. `samba` makes the client compute access from the directory and the file's permissions, and confirms the [Samba prerequisites](#samba-prerequisites) for that server. A server cannot have roots of both kinds. A `samba` root on a server that does not announce itself as Samba reports `unavailable`.

## Service account and keytab

Create a domain user account, for example `thero-connect`, that supports AES 128 and AES 256 Kerberos encryption. Its keytab is its password: keep it only in `/etc/thero-connect/krb5.keytab`. Create that folder first:

```bash
sudo install -d -m 0700 /etc/thero-connect
```

Active Directory, on the Linux host with msktutil (after `kinit` as a user allowed to create accounts):

```bash
sudo msktutil --create --use-service-account --account-name thero-connect \
  --enctypes 0x18 --keytab /etc/thero-connect/krb5.keytab --server dc01.corp.example
```

Active Directory, on a Windows admin host with ktpass. First tick "This account supports Kerberos AES 256 bit encryption" and "Password never expires" on the account. `/pass *` sets a new password, and `/princ` must match the account name exactly:

```
ktpass /princ thero-connect@CORP.EXAMPLE /mapuser CORP\thero-connect /pass * /crypto AES256-SHA1 /ptype KRB5_NT_PRINCIPAL /out krb5.keytab
```

Samba AD, on a domain controller:

```bash
samba-tool user create thero-connect --random-password
samba-tool user setexpiry thero-connect --noexpiry
samba-tool domain exportkeytab /root/krb5.keytab --principal=thero-connect@CORP.EXAMPLE
```

Copy the file to the Linux host over a secure channel. `klist -ke /etc/thero-connect/krb5.keytab` must show AES entries (`aes256-cts-hmac-sha1-96`, `aes128-cts-hmac-sha1-96`). The client uses AES only and ignores other entries, such as the `arcfour-hmac` entry that `samba-tool domain exportkeytab` also writes.

## Service account rights

All file servers:

- Share and file read on every configured root (never Modify).
- Member of "Windows Authorization Access Group" in the domain.

Windows file servers (as for the Windows client):

- Member of the local group "Power Users" on each file server, to read share permissions.
- Member of "Access Control Assistance Operators" on each file server, for remote access checks.
- Inbound firewall rule "Netlogon Service Authz (RPC)" enabled on each file server.

Samba file servers:

- SAMR access to the file server (the Samba default). Without it, allow entries for BUILTIN and server-local groups grant nothing, and deny entries for them always apply.

## SharePoint Server

A client with `url` roots indexes SharePoint Server site collections instead of file shares (see [config.yaml](../README.md#configyaml)). It still needs `principal`, the keytab and the directory access above. On the farm:

- Give the service account a Full Read user policy on the Default zone of every web application that holds a configured site collection: Central Administration, Manage web applications, User Policy, Add Users, zone Default, account `CORP\thero-connect`, permission Full Read. Full Read includes the permission to read role assignments; without it the root reports `denied` and has no readers.
- Register `HTTP/<host>` on the application pool account of the web application for every configured host, host-named site collections included, for example `setspn -S HTTP/intranet.corp.example CORP\sp-apppool`. When the service principal name differs from the host in `url`, set `spn` on the root.
- Enable Integrated Windows authentication with Negotiate (Kerberos) on the zone of `url`. The client uses Kerberos from its keytab only, never NTLM, and never delegates its credentials.
- The farm and its service principal names are in the same realm as `principal`. Cross-realm tickets are not supported.
- Extended Protection on the IIS site of the web application must be Off or Allow, not Require. With Require every request is refused and the root is `unavailable`.
- A certificate from an internal certification authority must be installed in the system trust store of the host, for example with `update-ca-certificates` on Debian and Ubuntu or `update-ca-trust` on RHEL. The client has no option to trust other certificates or to skip the check.
- The service needs direct outbound HTTPS to every configured SharePoint host. It never uses a proxy for SharePoint and never follows a redirect.

`check` prints `root <id> site` and `root <id> site users`; on failure it names the reason and the service principal name, for example a rejected Kerberos ticket, a redirect or an untrusted certificate. These details stay in the journal and are never sent to Thero.

## Samba prerequisites

Samba enforces settings that no client can read over the network. Setting `server: samba` for a server is the administrator's confirmation that all of the following hold for every configured share on it. If one does not hold, Thero can report readers that Samba refuses.

1. `vfs objects` contains `acl_xattr`, with `acl_xattr:ignore system acls = yes`, `acl_xattr:default acl style = windows` and `nt acl support = yes` (the default).
2. `acl_xattr` is the only module that handles ACLs: no `acl_tdb`, `zfsacl`, `nfs4acl_xattr` or `gpfs`.
3. The share root and every directory above it allow search for others (`o+x`), the share root allows `o+rx`, and the share root has no POSIX default ACL.
4. The share is changed and permissioned only through SMB below its root: no local `chmod`, `setfacl`, renames or file creation in the tree.
5. No `valid users`, `invalid users`, `force user`, `force group`, `username map`, `username map script` and no per-user `include`.
6. `follow symlinks = no`, `wide links = no` (the default) and `winbind nested groups = yes` (the default).
7. The idmap range of the domain covers every user and group of the domain, so no domain user is refused at logon.
8. The file server is a member or a domain controller of the domain of `principal`.

## Install

1. Download `thero-connect-linux-amd64` and `thero-connect-linux-amd64.sha256` from the latest release (on arm64 `thero-connect-linux-arm64` and its `.sha256` file), then:
   ```bash
   sha256sum -c thero-connect-linux-amd64.sha256
   sudo install -o root -g root -m 0755 thero-connect-linux-amd64 /usr/local/bin/thero-connect
   ```
2. Create the local service account:
   ```bash
   sudo useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin thero-connect
   ```
3. As root write `config.yaml` to `/etc/thero-connect` (created with the keytab above) and copy `krb5.keytab` there.
4. In Thero open the connector settings, choose Linux, click "Create install command" and run the command within 15 minutes. Leave out `-token` and paste the token when asked, so that it never appears in the process list or the shell history:
   ```bash
   sudo /usr/local/bin/thero-connect enroll -url wss://<host> -ca <fingerprint>
   ```
   It refuses links, a missing keytab, a folder, file or parent folder that root does not own, and a folder or parent folder that group or others can write to. It restricts the folder to root.
5. `sudo /usr/local/bin/thero-connect install -account thero-connect`
   This refuses a binary, or a folder above it, that root does not own or that group or others can write to, and an account whose primary group is shared with other users, gives the account read access to `config.yaml` and `krb5.keytab` and write access to `state/`, writes `/etc/systemd/system/thero-connect.service` and starts the service.
6. `sudo /usr/local/bin/thero-connect check`

`enroll`, `run`, `install` and `check` take `-dir <folder>` to use a folder other than `/etc/thero-connect`.

After `install`:

| Path | Owner | Mode |
|---|---|---|
| `/etc/thero-connect` | root:thero-connect | 0750 |
| `config.yaml`, `krb5.keytab` | root:thero-connect | 0640 |
| `state/` | root:thero-connect | 0770 |
| files in `state/` | thero-connect:thero-connect | 0600 |

## Operations

- Logs: `journalctl -u thero-connect`. Status: `systemctl status thero-connect`.
- Restart after a change of `config.yaml` or `krb5.keytab` with `sudo systemctl restart thero-connect`. The service does not reload the keytab on its own.
- The service restarts 60 seconds after any exit and never gives up.
- The client certificate is valid for 30 days and renews itself when less than 10 days remain. An expired certificate needs a new enrollment.
- Revoking the machine in Thero disconnects it at once. Reconnecting fails until it is enrolled again with a new install command.
- Enrolling again restricts the folder to root, so the service can no longer read it. Run `sudo /usr/local/bin/thero-connect uninstall` and `sudo /usr/local/bin/thero-connect install -account thero-connect` afterwards.
- `sudo /usr/local/bin/thero-connect uninstall` stops and removes the service. The account and the folder stay. To remove everything: `sudo userdel thero-connect; sudo rm -rf /etc/thero-connect`.
- The keytab and the client key in `state/identity.bin` are readable by root and the service account only. They are not encrypted at rest; use volume encryption (LUKS) against disk access.

### Keytab rotation

With msktutil, run the rotation as a root timer and check the flags against `man msktutil` of your version. `/etc/systemd/system/thero-connect-keytab.service`:

```ini
[Service]
Type=oneshot
ExecStart=/usr/sbin/msktutil --auto-update --use-service-account --account-name thero-connect --keytab /etc/thero-connect/krb5.keytab
ExecStartPost=/usr/bin/chown root:thero-connect /etc/thero-connect/krb5.keytab
ExecStartPost=/usr/bin/chmod 0640 /etc/thero-connect/krb5.keytab
ExecStartPost=/usr/bin/systemctl try-restart thero-connect
```

`/etc/systemd/system/thero-connect-keytab.timer`:

```ini
[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Enable it with `sudo systemctl enable --now thero-connect-keytab.timer`. After a rotation with ktpass or samba-tool, copy the new keytab and restart the service.

## Limits

- Group membership, identity mappings and share permissions take effect in Thero within 15 minutes; file permission edits with the next walk that reaches the file.
- Windows file servers decide every access check themselves, so the Linux and the Windows client report the same readers.
- Samba file servers: the client computes access and, when unsure, only ever reports fewer readers than Samba. Allow entries for domain-local groups on a Samba member server, for sIDHistory, for "This Organization" and for logon types grant nothing. A deny entry for a group whose membership cannot be proven (universal and distribution groups, groups with members from other domains, SIDs of other or old domains) applies to everyone. Files with conditional, object or claim entries, generic access bits or unsupported deny entries get no readers.
- An existing logon of a user can keep a removed group for the lifetime of the user's Kerberos tickets (up to 10 hours) and Samba's caches. Thero always reports the result of a fresh logon, as the Windows client does.
- The SMB pipes for share permissions and SAMR support only AES-128 encryption. A file server that requires encryption server-wide with AES-256 ciphers only reports `unavailable`. Encryption required per share works for walk and read.
- A clock skew over 5 minutes, unreachable domain DNS or no reachable global catalog makes roots `unavailable`.
- DFS namespaces, NTLM, LDAPS and gMSA are not supported.
- SharePoint limits are listed in [README.md](../README.md#sharepoint-server).
- For Samba file servers the client finds the domain controllers through DNS (`_ldap._tcp.dc._msdcs.<domain>`) and takes group memberships from any server that proves a Kerberos key for `ldap/<name>/<domain>`. Protect name resolution of the connector host (a trusted resolver, no unsolicited IPv6 router advertisements or DHCPv6) and allow only administrators to register `ldap/` service names. Windows file servers do not depend on this, because they decide every access check themselves.

## Build

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o thero-connect-linux-amd64 ./linux
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o thero-connect-linux-arm64 ./linux
```
