# Rust parity harness

The Rust backend was checked against the Python reference with
[rust-anything](https://github.com/erkamyaman/rust-anything) 3.3.0 (commit
`126ce42`), using the whole-app HTTP workflow (`app record` / `app replay`).

## What is here

- `rust/app-cases/http/` — 18 recorded HTTP cases (request, status, relevant
  headers and body). They were recorded from the Python backend before it was
  removed. `rust/app-cases/replay-report.md` is the Rust replay report.
- `parity/fakebin/` — deterministic `wg`, `wg-quick`, `iptables`,
  `iptables-restore`, `ip` and `sysctl` stand-ins. Every call is logged to
  `$FAKE_STATE/commands.log`; restore payloads go to `$FAKE_STATE/restore.log`.
- `parity/seed-data/` — synthetic clients, forwardings, server keys and a
  fixed `.secret_key`. Every key and the secret are obvious TEST values
  (`private-key-owner`, `0123456789abcdef0123456789abcdef`), not credentials.
  The recorded cases carry a session cookie signed with that test-only key.
- `parity/run_rust.sh` — copies the seed into `$FAKE_STATE/data`, sets the
  environment and starts `target/release/portbridge` on the requested port.

## Replay

```sh
cargo build --release
export FAKE_STATE="$PWD/parity/state"
rust-anything app replay . --build "bash parity/run_rust.sh {port}"
```

Expected: `18/18 cases passed`.

## Persistent-state parity

During the migration the same requests were sent through the Python and Rust
servers, and the resulting `clients.json`, `forwardings.json`, WireGuard
configs, client profiles, command log and `iptables-restore` payloads were
compared. The result was `10/10 files match` after normalising the single
`created_at` timestamp of a client created during the run. Those generated
copies are not committed.
