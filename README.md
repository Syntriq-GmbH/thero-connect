# Thero Connect

Thero Connect is a small service in your network that lets Thero index SMB file shares and SharePoint Server site collections and enforce their read permissions without any inbound port. It dials out to Thero over WebSocket with mutual TLS 1.3 and answers four read requests that Thero drives. Thero never gets a route into your network and never holds an SMB, SharePoint or Active Directory password. Nothing is ever written to a file share or to SharePoint.

Only this leaves the network:

- file metadata (path, size, times, a permission class) of the configured roots,
- for SharePoint roots also the paths, links and titles of webs, lists, files, list items and attachments, and the text of visible list item fields,
- the bytes of files Thero asks for (for SharePoint only published versions),
- the Active Directory accounts whose email matches the email of a Thero member,
- the list of readers per permission class.

Only SIDs and reader indexes travel for permissions. SharePoint login names, service principal names, redirect targets and authentication details stay in the local log and in the output of `check`.

## Platforms

| Platform | Release file | Guide |
|---|---|---|
| Windows Server, amd64 | `thero-connect.exe` | [windows/README.md](windows/README.md) |
| Windows Server and Windows on ARM, arm64 | `thero-connect-arm64.exe` | [windows/README.md](windows/README.md) |
| Linux, amd64 | `thero-connect-linux-amd64` | [linux/README.md](linux/README.md) |
| Linux, arm64 | `thero-connect-linux-arm64` | [linux/README.md](linux/README.md) |

Every release file has a `.sha256` file next to it. Both clients speak the same protocol and read the same `config.yaml`. For a Windows file server they report the same readers, because there the file server decides every access check. For SharePoint Server both run the same decision in the shared core and ask SharePoint the same questions, so they report the same readers too. The Linux client can also index shares on Samba servers in an Active Directory domain.

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

A client indexes either file shares or SharePoint Server site collections. All roots of one client are of one kind: every root has `path`, or every root has `url`. For SharePoint the format is:

```yaml
principal: thero-connect@CORP.EXAMPLE
roots:
  - id: intranet
    url: https://intranet.corp.example/sites/hr
  - id: projects
    url: https://projects.corp.example
    spn: HTTP/sp01.corp.example
    exclude:
      - Site Assets
      - Lists/Archive
limits:
  max_file_mb: 20
  max_gb_per_day: 50
  max_mbit: 40
  read_window: "19:00-07:00"
```

- `url`: the URL of a site collection (not of a web or list) on SharePoint Server 2016, 2019 or Subscription Edition. `https` only, without user name, query or fragment. Use the URL of the Default zone that uses Windows authentication. `check` and every walk confirm that the URL names a site collection; otherwise the root fails.
- `spn`: optional, only with `url`. The Kerberos service principal name of the web application, `HTTP/<host>` with an optional `:<port>`. The default is `HTTP/` plus the host of `url`, without a port and without a DNS lookup.
- `server` is only for file shares. `exclude` is matched against the path relative to the site collection, for example `Shared Documents/Archive` or `Lists/Tickets`.
- `proxy` and `HTTPS_PROXY` apply to the link to Thero only. SharePoint is always contacted directly.

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

### SharePoint Server

- A person reads an object only when both agree: the role assignments, SharePoint groups and site collection administrators of the object, matched against the person's current Active Directory groups, and SharePoint's own answer for that person (`GetUserEffectivePermissions`). Each must grant View Items, View Application Pages, Open Items, Open and View Pages.
- A person must have a row in the site collection's user list whose login and SID equal the person's current account. People who never opened a site collection have no row and are not readers there. An account deleted and created again under the same name is not a reader while the user list row still carries the SID of the old account.
- Only the current version of a file or list item is indexed, and only when it is a published, approved major version. Drafts, minor versions, pending or rejected items and checked out files that were never checked in are not indexed, and there is no fallback to an older version.
- In lists with "Read items that were created by the user", only the author of an item is a reader, and only when the author may also read the item.
- View Only and Limited Access grant nothing, also for list items, because they lack Open Items or View Items.
- Pages (`.aspx`) in libraries, hidden lists, catalogs, lists with Information Rights Management and webs or lists excluded from search (`NoCrawl`) are not indexed. Attachments whose name contains `#` or `%` are skipped.
- Readers given through SAML, forms or other claim providers, local groups and groups of other domains grant nothing. Web application user policies only remove readers: their grants are ignored, their denies come from SharePoint's answer. Policies of zones other than the one in `url` are not evaluated.
- Folders are part of the path. A renamed or moved file, item or folder is deleted in Thero and indexed again under its new path.
- Kerberos only, never NTLM. HTTPS only with TLS 1.2 or later, HTTP/1.1, the system trust store, no proxy, no cookies and no redirects. A redirect, a forms login or a SAML only zone makes the root `unavailable`.
- Every request is checked against an allow list before it is sent: `GET` below `/_api/` of the site collection and of webs the walk found, and `POST` only to `_api/contextinfo` and `_api/site/getchanges` of the site collection. No other method or path is ever sent.
- Every rights cycle (5 minutes) reads the site collection's change log and lists again what it names; a full walk runs every 30 minutes. Content changes, broken or restored inheritance and changed role assignments usually reach Thero within one cycle; group membership in Active Directory within 15 minutes, as for file shares. Changes only SharePoint knows, such as a web application policy, reach Thero within about 30 minutes.
- On a large farm the first rights cycles check part of the readers and report the rest as no readers until the answers are cached, usually within a few cycles. A busy farm is never retried more than twice per request.
- The client keeps what it learned about a site collection in memory only. After a restart the root has no readers and no reads until the next full walk, which Thero starts on every new connection.
- Whether downloads through Thero leave entries in SharePoint audit logs or usage analytics is an open lab check (L15 in [AGENTS.md](AGENTS.md#sharepoint-farm-checklist)). This section records the result once it is known.

## Protocol

`protocol/v1` holds the protocol: a JSON schema, fixtures and `chunk.bin`. The Thero server keeps a byte-identical copy, and `TestDigest` in `core/protocol_test.go` pins it. A breaking change creates `protocol/v2`. SharePoint added four optional fields to v1: `changes` on `walk` (an incremental walk), `deleted` on `page` (paths whose records are removed), and `url` and `title` on page entries (the browser link and the display name of a list item). Their fixtures are in `protocol/v1/fixtures/sharepoint/`. Older peers ignore the fields or answer `bad_request`, and readers stay exact in every pairing. The `enroll` and `hello` messages name the client version and platform, for example `1.4.0 linux/arm64`.

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

`core/` holds the shared client: configuration, commands, link, request handlers and the permission logic. `windows/` and `linux/` each hold the file share access, directory reads, Kerberos and system integration of one operating system. `core/sharepoint.go` holds everything specific to SharePoint Server. `test/samba/` is a Samba Active Directory lab in Docker that checks the Linux client against real SMB opens and Kerberos to a local HTTPS server. [AGENTS.md](AGENTS.md) has the full command list and the contribution rules.

Releases: pushing a tag `vX.Y.Z` runs the release workflow. It tests, builds the four files of the platform table with the version from the tag and publishes them with their `.sha256` files as one GitHub release.
