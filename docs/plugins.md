# Writing a backend plugin

A vault with `backend = "plugin"` runs an executable — `command = "/path/to/tool"`, or
`type = "name"` for `sx-backend-name` on `PATH`. sx calls it once per operation:
one JSON object on stdin, one on stdout. Exit code 0 even for "not found"; report errors in JSON.

The plugin runs inside the `sx` process **after** Sx.app approved the request, so it does not
need its own prompting. It must never print secret values anywhere except its stdout reply.

## Requests

```json
{"op": "get",  "name": "ci/token", "vault": "hc", "settings": {"backend": "plugin", "type": "hashicorp", "addr": "…"}}
{"op": "list", "vault": "hc", "settings": {…}}
```

`settings` is every string key of the vault's `[vault.<name>]` table, so plugins can take their
own options (`addr`, `mount`, `profile`, …).

## Replies

```json
{"ok": true, "value": "<base64 of the secret bytes>"}
{"ok": true, "names": ["ci/token", "deploy/key"]}
{"ok": false, "error": "not found: ci/token"}
```

## Minimal example (shell)

```bash
#!/bin/bash
# sx-backend-envdir: secrets are files in $SX_ENVDIR (demo only)
read -r req
op=$(jq -r .op <<<"$req"); name=$(jq -r '.name // empty' <<<"$req")
dir=$(jq -r '.settings.dir' <<<"$req")
case $op in
  get)  [ -f "$dir/$name" ] && printf '{"ok":true,"value":"%s"}\n' "$(base64 < "$dir/$name")" \
                            || printf '{"ok":false,"error":"not found"}\n' ;;
  list) printf '{"ok":true,"names":%s}\n' "$(cd "$dir" && find . -type f | sed 's|^\./||' | jq -R . | jq -s .)" ;;
esac
```
