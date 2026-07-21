# Muninn Context Receipt

Muninn is zero-trust context governance for AI-authored code. It posts a
**Context Receipt** comment on your pull requests: an audit of the repo's
context surfaces (CLAUDE.md, AGENTS.md, .cursor/rules, and similar files
that steer an AI agent), not a code-quality or security review. Muninn
never approves code and never blocks a merge. It gives a reviewer one more
signal, nothing more.

## The two locks

Muninn is built around two guarantees, enforced by the architecture, not by
a promise:

1. **Your content never leaves your machine.** This client redacts and
   fingerprints your repo's context surfaces locally, inside your own CI
   runner. What gets sent to the server is a signed bundle of redacted
   pointers and fingerprints, never raw file contents.
2. **Our engine never lands on your machine.** This repo contains no
   scoring engine, no scoring logic, and no code that could reconstruct
   your content from what it sends. Scoring happens on a server you
   configure, over the bundle this client already redacted.

## This repo IS the client. Read it.

Everything that runs inside your CI job lives in `shadow/` in this repo,
in plain Python, with no obfuscation and no compiled artifacts. There is no
hidden binary, no vendored engine, and no code path that reads your files
and sends them anywhere raw. Specifically:

- `shadow/pr_action.py` is the entry point. It only runs in **server
  mode**: if you have not configured a scoring server (`MUNINN_SERVER_URL`),
  it fails immediately with a clear error instead of doing anything else.
  It has no local scoring fallback.
- `shadow/bundle.py` + `shadow/_bundle_primitives.py` assemble the bundle
  that gets sent: redacted pointers, fingerprints, and hashes, never raw
  file bodies.
- `shadow/signing.py` signs that bundle with your own ed25519 key before it
  ever touches the network, and verifies the server's signature on
  whatever comes back, before this client trusts or renders it.
- `shadow/server_client.py` is the only module that makes a network call.

If you want to verify Muninn cannot exfiltrate your code, this is the whole
surface area to read. There is no other client code running anywhere else.

## Quickstart

Add a workflow to your repo (`.github/workflows/muninn.yml`):

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
      - uses: bronsonaber/muninn-client@main
        with:
          server-url: 'https://muninn-edge.bronson-aber.workers.dev'
          server-pubkey: ${{ vars.MUNINN_SERVER_PUBKEY }}
          client-key-id: ${{ vars.MUNINN_CLIENT_KEY_ID }}
          client-private-key: ${{ secrets.MUNINN_CLIENT_PRIVATE_KEY_PEM }}
```

Before that workflow can produce a receipt, you need a signing key
registered with the server. See `PROVISIONING.md` for the full self-serve
`/register` flow: generate a keypair with `shadow.keygen`, register it, and
wire the resulting values into the workflow above.

## What a receipt is not

A Context Receipt is not a code review, not a security scan, and not a
merge gate. It never blocks anything and Muninn's action never fails your
build because of what it finds in your context surfaces. It is a signal
about how well the repo's own AI-facing instructions hold up, posted where
a human reviewer will see it alongside everything else on the PR.
