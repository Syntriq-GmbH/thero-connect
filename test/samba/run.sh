#!/usr/bin/env bash
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
out=$here/out
admin='Adm1n#Thero2026'
golang=golang:1.27@sha256:e519d3b0a5b285e5aa53ab9eef02bc6bbb9cb04608389b743a136a9ce75f0d1e
files="alice/plan.txt shared/handbook.txt finance/budget.txt nested/n.txt hidden/secret.txt order/allow-first.txt dl/report.txt builtin/users.txt owner/rights.txt noread/attrs.txt dlfsp/x.txt builtindeny/x.txt aliasdeny/x.txt busy/held.txt"
export COMPOSE_FILE=$here/compose.yaml
export THERO_SMB_PROJECT=${THERO_SMB_PROJECT:-thero-smb} THERO_SMB_NET=${THERO_SMB_NET:-172.30.53}

dc() { docker compose exec -T dc1 "$@"; }
fs() { docker compose exec -T fs1 "$@"; }
smb() {
  local output
  output=$(dc "$@" 2>&1) || { echo "$output" >&2; exit 1; }
  if grep -q NT_STATUS <<<"$output"; then echo "$output" >&2; exit 1; fi
}
wait_for() { for _ in $(seq 90); do "$@" >/dev/null 2>&1 && return 0; sleep 2; done; "$@"; }
sid() { dc samba-tool user show "$1" --attributes=objectSid | sed -n 's/^objectSid: //p'; }

gotest() {
  docker run --rm --network "$THERO_SMB_PROJECT" --dns "$THERO_SMB_NET.10" --dns-search samdom.example.com \
    -v "$repo":/src -w /src -v "$THERO_SMB_PROJECT-gocache":/root/.cache -v "$THERO_SMB_PROJECT-gomod":/go/pkg/mod \
    -e THERO_SAMBA_DIR=/src/test/samba/out "$golang" \
    go test -tags samba -race -run "$1" -count=1 -v ./linux
}

tree() {
  local server=$1 client="smbclient //$1.samdom.example.com" acl="smbcacls //$1.samdom.example.com" auth=(-U "SAMDOM\\administrator%$admin")
  local base="ACL:S-1-5-32-544:ALLOWED/0/FULL,ACL:SAMDOM\\svc-thero:ALLOWED/0/READ"
  local shares=docs
  [ "$server" = fs1 ] && shares="docs restricted ownerrights"
  for share in $shares; do
    docker compose exec -T "$server" samba-tool ntacl set --use-s3fs --service="$share" \
      "O:BAG:BAD:(A;OICI;0x1f01ff;;;BA)(A;OICI;0x1200a9;;;$svc)(A;CI;0x1200a9;;;${svc%-*}-513)" "/srv/$share"
    docker compose exec -T "$server" chmod 0775 "/srv/$share"
  done
  dc bash -c 'for f in "$@"; do printf "Content of %s" "$f" > "/tmp/content.${f//\//_}"; done' _ $files
  dc bash -c "printf 'Alice only: kestrel-7341' > /tmp/content.alice_plan.txt; printf 'Shared handbook: heron-2958' > /tmp/content.shared_handbook.txt"
  local commands="mkdir link; "
  for f in $files; do
    commands+="mkdir ${f%%/*}; put /tmp/content.${f//\//_} $f; "
  done
  smb $client/docs "${auth[@]}" -c "$commands"
  dc $acl/docs alice/plan.txt "${auth[@]}" --set "$base,ACL:SAMDOM\\alice:ALLOWED/0/READ"
  dc $acl/docs shared/handbook.txt "${auth[@]}" --set "$base,ACL:SAMDOM\\Domain Users:ALLOWED/0/READ"
  dc $acl/docs finance/budget.txt "${auth[@]}" --set "$base,ACL:SAMDOM\\Finance:ALLOWED/0/READ"
  dc $acl/docs nested/n.txt "${auth[@]}" --set "$base,ACL:SAMDOM\\Outer:ALLOWED/0/READ"
  dc $acl/docs hidden/secret.txt "${auth[@]}" --set "$base,ACL:SAMDOM\\bob:DENIED/0/READ,ACL:SAMDOM\\Domain Users:ALLOWED/0/READ"
  dc $acl/docs dl/report.txt "${auth[@]}" --set "$base,ACL:SAMDOM\\DL_Report:ALLOWED/0/READ"
  dc $acl/docs builtin/users.txt "${auth[@]}" --set "$base,ACL:S-1-5-32-545:ALLOWED/0/READ"
  dc $acl/docs owner/rights.txt "${auth[@]}" --set "OWNER:SAMDOM\\alice,$base,ACL:S-1-3-4:ALLOWED/0/READ"
  dc $acl/docs noread/attrs.txt "${auth[@]}" --set "$base,ACL:S-1-1-0:ALLOWED/0/0x00000080"
  dc $acl/docs dlfsp/x.txt "${auth[@]}" --set "$base,ACL:SAMDOM\\Domain Users:ALLOWED/0/READ,ACL:SAMDOM\\DL_DenyAU:DENIED/0/0x00000001"
  dc $acl/docs builtindeny/x.txt "${auth[@]}" --set "$base,ACL:SAMDOM\\Domain Users:ALLOWED/0/READ,ACL:S-1-5-32-545:DENIED/0/0x00000001"
  dc $acl/docs aliasdeny/x.txt "${auth[@]}" --set "$base,ACL:SAMDOM\\Domain Users:ALLOWED/0/READ,ACL:S-1-5-32-546:DENIED/0/0x00000001"
  dc $acl/docs busy/held.txt "${auth[@]}" --set "ACL:S-1-5-32-544:ALLOWED/0/FULL,ACL:SAMDOM\\svc-thero:ALLOWED/0/FULL"
  docker compose exec -T "$server" samba-tool ntacl set --use-s3fs --service=docs \
    "O:BAG:BAD:(A;;0x1f01ff;;;BA)(A;;0x1200a9;;;$svc)(A;;0x1200a9;;;WD)(D;;0x1200a9;;;$bob)" /srv/docs/order/allow-first.txt
  docker compose exec -T "$server" ln -s ../shared/handbook.txt /srv/docs/link/h.txt
  if [ "$server" = fs1 ]; then
    smb $client/restricted "${auth[@]}" -c "mkdir r; put /tmp/content.shared_handbook.txt r/doc.txt"
    dc $acl/restricted r/doc.txt "${auth[@]}" --set "$base,ACL:SAMDOM\\Domain Users:ALLOWED/0/READ"
    smb $client/ownerrights "${auth[@]}" -c "mkdir o; put /tmp/content.shared_handbook.txt o/doc.txt"
    dc $acl/ownerrights o/doc.txt "${auth[@]}" --set "$base,ACL:SAMDOM\\Domain Users:ALLOWED/0/READ"
    fs sharesec restricted --replace "S-1-1-0:ALLOWED/0/FULL,$bob:DENIED/0/FULL"
    fs sharesec ownerrights --replace "S-1-3-4:ALLOWED/0/READ,$svc:ALLOWED/0/READ"
  fi
}

truth() {
  local servers=$1 who=$2 target=$3
  dc bash -s "$servers" "$who" "$files" <<'EOF' > "$target"
set -u
declare -A pass=([alice]='Alice#Pass2026' [bob]='Bob#Pass2026' [dave]='Dave#Pass2026')
for user in $2; do
  echo "${pass[$user]}" | KRB5CCNAME=/tmp/cc.$user kinit "$user@SAMDOM.EXAMPLE.COM" >/dev/null 2>&1 || true
done
first=1
echo "["
for server in $1; do
  list=""
  for f in $3; do list+="docs:$f "; done
  [ "$server" = fs1 ] && list+="restricted:r/doc.txt ownerrights:o/doc.txt"
  for item in $list; do
    share=${item%%:*} path=${item#*:}
    for user in $2; do
      kerberos=$(smbclient "//$server.samdom.example.com/$share" --use-kerberos=required --use-krb5-ccache=/tmp/cc.$user -c "get $path /dev/null" 2>&1) && ! grep -q NT_STATUS <<<"$kerberos" && k=1 || k=0
      ntlm=$(smbclient "//$server.samdom.example.com/$share" --use-kerberos=disabled -U "SAMDOM\\$user%${pass[$user]}" -c "get $path /dev/null" 2>&1) && ! grep -q NT_STATUS <<<"$ntlm" && n=1 || n=0
      read=false
      [ "$k$n" = 11 ] && read=true
      [ "$k" != "$n" ] && echo "methods differ: $server $share $path $user kerberos=$k ntlm=$n" >&2
      [ $first = 1 ] || echo ","
      first=0
      printf '{"server":"%s","share":"%s","path":"%s","user":"%s","read":%s}' "$server" "$share" "$path" "$user" "$read"
    done
  done
done
echo "]"
EOF
}

case "${1:-}" in
up)
  "$0" down
  mkdir -p "$out"
  docker compose build
  docker compose up -d dc1
  wait_for dc bash -c "echo '$admin' | kinit administrator@SAMDOM.EXAMPLE.COM"
  test "$(dc testparm -s --parameter-name='ldap server require strong auth' 2>/dev/null)" = Yes
  for user in alice bob carol erin; do
    password="$(tr '[:lower:]' '[:upper:]' <<<"${user:0:1}")${user:1}#Pass2026"
    dc samba-tool user create "$user" "$password" --mail-address="$user@samdom.example.com"
  done
  dc samba-tool user disable carol
  dc samba-tool user create svc-thero 'Svc#Thero-2026-long-random'
  dc samba-tool user setexpiry svc-thero --noexpiry
  dc samba-tool group addmembers "Windows Authorization Access Group" svc-thero
  dc samba-tool group add Finance
  dc samba-tool group addmembers Finance alice
  dc samba-tool group add Outer
  dc samba-tool group addmembers Outer Finance
  dc samba-tool group add DL_Report --group-scope=Domain
  dc samba-tool group addmembers DL_Report alice
  dc samba-tool group add DL_DenyAU --group-scope=Domain
  printf 'dn: CN=DL_DenyAU,CN=Users,DC=samdom,DC=example,DC=com\nchangetype: modify\nadd: member\nmember: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=samdom,DC=example,DC=com\n' | dc ldbmodify -H /var/lib/samba/private/sam.ldb
  dc bash -c 'mkdir -p /srv/docs && chmod 0755 /srv /srv/docs && printf "\n[docs]\n\tpath = /srv/docs\n\tread only = no\n\tvfs objects = dfs_samba4 acl_xattr\n\tacl_xattr:ignore system acls = yes\n\tacl_xattr:default acl style = windows\n\tfollow symlinks = no\n" >> /etc/samba/smb.conf && smbcontrol all reload-config'
  docker compose up -d fs1
  wait_for fs wbinfo -t
  dc getent hosts fs1.samdom.example.com >/dev/null || dc samba-tool dns add dc1.samdom.example.com samdom.example.com fs1 A "$THERO_SMB_NET.20" -U "administrator%$admin"
  dc samba-tool user create dave 'Dave#Pass2026' --mail-address=dave@samdom.example.com
  fs net sam createbuiltingroup Guests
  fs net sam createlocalgroup LocalGuests
  fs net sam addmem LocalGuests 'SAMDOM\alice'
  fs net sam addmem Guests 'FS1\LocalGuests'
  bob=$(sid bob) svc=$(sid svc-thero)
  tree dc1
  tree fs1
  dc samba-tool spn add HTTP/localhost svc-thero
  dc samba-tool domain exportkeytab /tmp/svc-thero.keytab --principal=svc-thero@SAMDOM.EXAMPLE.COM
  dc samba-tool domain exportkeytab /tmp/http.keytab --principal=HTTP/localhost@SAMDOM.EXAMPLE.COM
  docker compose cp dc1:/tmp/svc-thero.keytab "$out/krb5.keytab"
  docker compose cp dc1:/tmp/http.keytab "$out/http.keytab"
  dc rm /tmp/svc-thero.keytab /tmp/http.keytab
  chmod 0600 "$out/krb5.keytab" "$out/http.keytab"
  ;;
fresh)
  gotest '^TestSambaFresh$'
  dc samba-tool user disable erin
  ;;
truth)
  truth "dc1 fs1" "alice bob dave" "$out/truth.json"
  for user in alice bob; do
    echo "$user" $(dc ldbsearch -H /var/lib/samba/private/sam.ldb -b "CN=$user,CN=Users,DC=samdom,DC=example,DC=com" -s base objectSid tokenGroups | awk '/^(objectSid|tokenGroups): /{print $2}')
  done > "$out/groups.txt"
  echo "truth: $(grep -o '"read":true' "$out/truth.json" | wc -l | tr -d ' ') of $(grep -o '"read":' "$out/truth.json" | wc -l | tr -d ' ') reads succeed"
  ;;
test)
  gotest '^TestSamba(|Negotiate|Members)$'
  ;;
idmap)
  grep -q '"server":"fs1","share":"docs","path":"shared/handbook.txt","user":"dave","read":true' "$out/truth.json"
  rid=$(sid dave | sed 's/.*-//')
  IDMAP_RANGE="10000-$((10000 + rid - 1))" docker compose up -d --force-recreate fs1
  wait_for fs wbinfo -t
  truth fs1 dave "$out/truth-idmap.json"
  if grep -q '"read":true' "$out/truth-idmap.json"; then
    echo "idmap: dave reads on fs1 with an idmap range below his RID" >&2
    exit 1
  fi
  echo "idmap: dave (RID $rid) reads nothing on fs1 with range 10000-$((10000 + rid - 1))"
  ;;
down)
  docker compose down --volumes --remove-orphans
  docker volume rm -f "$THERO_SMB_PROJECT-gocache" "$THERO_SMB_PROJECT-gomod" >/dev/null
  rm -rf "$out"
  ;;
*)
  echo "usage: $0 up|fresh|truth|test|idmap|down" >&2
  exit 2
  ;;
esac
