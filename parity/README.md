# Rust parity harness

The Rust backend was checked against the Python reference with
[rust-anything](https://github.com/erkamyaman/rust-anything) 3.3.0 (commit
`126ce42`), using the whole-app HTTP workflow (`app record` / `app replay`).

## What is here

- `rust/app-cases/http/` — 18 recorded HTTP cases (request, status, relevant
  headers and body). The request/response behaviour was recorded from the
  Python backend before it was removed; the Cookie headers and Set-Cookie
  expectations were then adjusted to the opaque server-side session scheme.
  `rust/app-cases/replay-report.md` is the Rust replay report.
- `parity/fakebin/` — deterministic `wg`, `wg-quick`, `iptables`,
  `iptables-restore`, `ip` and `sysctl` stand-ins. Every call is logged to
  `$FAKE_STATE/commands.log`; restore payloads go to `$FAKE_STATE/restore.log`.
- `parity/seed-data/` — synthetic clients, forwardings, server keys, a fixed
  `.secret_key` and a `sessions.json` containing one opaque test session token.
  Every key, token and the secret are obvious TEST values, not credentials.
  The recorded cases carry that opaque token; its password tag is an HMAC-SHA256
  of `parity-password-123` under the fixture secret key. Sessions are now server-side and opaque, so the old
  Flask cookies are deliberately rejected and require one login after upgrade.
- `parity/run_rust.sh` — copies the seed into a fresh run directory under `$FAKE_STATE`, sets the
  environment and starts `target/release/portbridge` on the requested port.

## Replay

```sh
cargo build --release
export FAKE_STATE="$(mktemp -d)"
rust-anything app replay . --build "bash parity/run_rust.sh {port}"
```

Expected: `18/18 cases passed`.

## Persistent-state parity

During the migration the same requests were sent through the Python and Rust
servers, and the resulting `clients.json`, `forwardings.json`, WireGuard
configs, client profiles, command log and `iptables-restore` payloads were
compared. The result was `10/10 files match` after normalising the single
`created_at` timestamp of a client created during the run. `sessions.json` is
excluded from that comparison because its tokens are random per login; the
session behaviour is covered by the Rust auth tests. Those generated copies
are not committed.
