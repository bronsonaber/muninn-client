# Client key provisioning for Muninn

This client (`shadow/pr_action.py`) runs in SERVER MODE only: it never
scores your code itself. It assembles a redacted, signed fingerprint bundle
locally and hands scoring to a configured Muninn scoring server
(`MUNINN_SERVER_URL`). Every bundle it sends is signed with your own
ed25519 client key, so the server can tell your repo's requests apart from
anyone else's and reject anything it does not recognize.

Registering a public key with the server is self-service: you run
`shadow.keygen` locally, then POST the printed public key (plus a one-time
invite token we hand you) to `POST /register` and get back everything else
in one call: the server's own public key, your dashboard URL, and a
dashboard bearer token. The keypair itself, and everything your CI needs to
use it, is generated and wired entirely by the tools below.

## Step 1: generate a keypair

From this repo (or wherever `shadow/keygen.py` is available):

```bash
python3 -m shadow.keygen
```

This:
- generates a new ed25519 keypair locally (no network call),
- writes the **private** key to `muninn_client_key.pem` in your current
  directory (owner-read/write only where the platform supports it),
- prints **only** the public key (PEM) and a `key_id` to your terminal.

The private key is never printed to the terminal and never sent anywhere by
this command. If you want a different output path, pass `--out`:

```bash
python3 -m shadow.keygen --out /somewhere/private/muninn_client_key.pem
```

## Step 2: register the public key (self-service)

You will have received a one-time **enrollment invite token** from us out
of band (email, or wherever we already send you your account details).
POST it, your `key_id`, and the public key PEM from step 1 to `/register`
in one call:

```bash
curl -sS -X POST "https://muninn-edge.bronson-aber.workers.dev/register" \
  -H 'content-type: application/json' \
  -d "$(python3 - <<PY
import json
print(json.dumps({
    "enrollment_token": "<the invite token we gave you>",
    "key_id": "<key_id printed by shadow.keygen>",
    "public_key_pem": open("muninn_client_key.pub.pem").read(),  # or paste it inline
}))
PY
)"
```

(Adjust the pubkey source to however you saved step 1's printed PEM --
`shadow.keygen` prints it to stdout, it does not write it to a file.)

On success (`200`), the response is:

```json
{
  "server_url": "https://muninn-edge.bronson-aber.workers.dev",
  "server_pubkey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "dashboard_url": "https://muninn-edge.bronson-aber.workers.dev/dashboard.html?key_id=cust_...",
  "dashboard_token": "<a raw bearer token -- shown exactly once, save it now>"
}
```

- `server_url` / `server_pubkey` are what step 4 below wires into your CI
  workflow (`server-url` / `server-pubkey` inputs).
- `dashboard_url` + `dashboard_token` get you to your Context Health
  dashboard (`Authorization: Bearer <dashboard_token>` header on the
  `dashboard_url`'s base URL, or open `dashboard_url` and add the header
  with any HTTP client -- a bearer token cannot be embedded in a plain
  browser link).
- The invite token is **single-use**: a second call with the same token is
  rejected. If you registered the wrong `key_id` or a malformed pubkey by
  mistake, that specific failure does **not** consume the invite -- retry
  the same call with the correction.
- The private key never appears anywhere in this exchange. Do **not** send
  it. It never leaves your machine.

## Step 3: store the private key as a repo secret

1. Open the file `python3 -m shadow.keygen` wrote (default
   `muninn_client_key.pem`) and copy its full contents.
2. In your repo (or org) on GitHub: **Settings -> Secrets and variables ->
   Actions -> New repository secret**, name it
   `MUNINN_CLIENT_PRIVATE_KEY_PEM`, and paste the PEM as the value.
3. Set the `key_id` printed in step 1 somewhere your workflow can read it
   (a plain repo variable or another secret both work; it is not
   sensitive) -- you will pass it as `client-key-id` below.

## Step 4: wire it into your workflow

```yaml
on: pull_request
permissions:
  pull-requests: write
  contents: read
jobs:
  context-receipt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: bronsonaber/muninn-client@__MUNINN_CLIENT_PIN_SHA__  # pinned: v0.1
        with:
          server-url: 'https://muninn-edge.bronson-aber.workers.dev'
          server-pubkey: ${{ vars.MUNINN_SERVER_PUBKEY }}
          client-key-id: ${{ vars.MUNINN_CLIENT_KEY_ID }}
          client-private-key: ${{ secrets.MUNINN_CLIENT_PRIVATE_KEY_PEM }}
```

**Always pin `uses:` to a full 40-character commit SHA, never `@main` or a
version tag.** This job runs with access to your repo's raw files and
secrets BEFORE Muninn's own redaction step ever fires. A mutable ref means
that if `muninn-client`'s `main` branch (or a tag) were ever moved --
accidentally, or by a compromised maintainer account -- to point at
different, unreviewed code, your CI would start running that code the very
next time this workflow triggered, with no change to your own workflow
file at all. A pinned SHA cannot be moved out from under you: bumping it is
always a deliberate, visible action in your own repo (a diff to this file).

`muninn init` (the self-service installer) always writes the workflow with
the pinned SHA baked in already; the block above is for anyone wiring this
by hand or reviewing what `muninn init` generated.

The client's own `check_pinned_ref()` self-check (`shadow/pr_action.py`)
also enforces this at run time: it reads `GITHUB_ACTION_REF` (set by the
GitHub Actions runner itself for this invocation, not something your
`with:` inputs can override) and FAILS the job if it is not a
40-character commit SHA. If you deliberately need to run against a branch
or tag for local testing, set `MUNINN_ALLOW_UNPINNED=true` in that job's
`env:` -- this is a documented escape hatch, not a recommendation, and the
job still prints a SECURITY WARNING when it is used.

**Version-rotation / security-bulletin policy:** we cut immutable
`muninn-client` releases (a tagged commit) rather than developing against
`main` in place. When we ship a fix worth adopting -- especially a
security fix -- we publish a bulletin naming the new commit SHA; bump the
pinned SHA in your workflow at that point. There is no "auto-update" by
design: your CI never changes behavior without your own commit to your
own workflow file.

`server-url` and `server-pubkey` are exactly the `server_url` /
`server_pubkey` fields step 2's `/register` response returned (or, under
the manual fallback below, whatever we hand you); `client-key-id` /
`client-private-key` are what steps 1-3 above produced. `server-url` is
required: this client has no local scoring mode, so leaving it unset makes
the action fail immediately with a clear error instead of running.

### Fallback: manual registration

If self-service is unavailable for some reason, the old manual path still
works: send us the `key_id` and public key PEM printed in step 1, and we
register it and hand you a dashboard token by hand. Everything else above
is unchanged either way.

## Step 5: delete the local private-key file

Once the secret is saved in step 3, delete the local
`muninn_client_key.pem` (or whatever `--out` path you used). It is
plaintext private key material sitting on disk and has no further purpose
once it is a GitHub secret.

## What happens if you skip client key registration

If `client-key-id` / `client-private-key` are left empty (but `server-url`
is set), the client does not fail to run: it falls back to generating a
fresh **ephemeral** keypair for that run only. An ephemeral key can never
have been registered in advance, so the server will reject it every time.
The action logs a one-line notice explaining exactly that ("using a fresh
EPHEMERAL, UNREGISTERED signing key... the server will reject it until its
public key is registered") so the resulting "no receipt available this
run" reads as an expected consequence of skipping provisioning, not a
mysterious failure.
