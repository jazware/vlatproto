# vlatproto

atproto as vlpds and vlRelay speak it, in one crate: the repo data model
(DAG-CBOR, CIDs, TIDs, CARs and their streamable block order, the MST),
K-256 keys with hedged, verified signing, firehose frames (built in `events`,
read back in `frame`), PLC operation types, identifier syntax, DID resolution
over shared outbound HTTP clients (one of them SSRF-guarded), and XRPC
errors and admin-token checks.

Its public home is [github.com/jazware/vlatproto](https://github.com/jazware/vlatproto).
[vlsync](https://github.com/jazware/vlsync) (the storage layer and the
firehose), [vlpds](https://github.com/jazware/vlpds) and
[vlRelay](https://github.com/jazware/vlrelay) build on it.

| Module | What |
|--------|------|
| `cbor`, `cid`, `tid`, `car`, `car_order`, `mst` | The repo data model |
| `crypto` | secp256k1 keys (libsecp256k1), did:key and multikey, hedged signatures verified before use, the fail-stop after repeated faults |
| `events`, `frame` | subscribeRepos frames, encoded with the seq spliced in last, and read back without decoding (type, DID, `#info`) |
| `plc`, `syntax`, `did_resolver` | PLC operation types, identifier syntax, DID resolution |
| `http`, `xrpc` | The shared outbound clients (`public`, the SSRF-guarded `guarded`), XRPC errors and admin-token checks |

## Using it

```toml
[dependencies]
vlatproto = { git = "https://github.com/jazware/vlatproto", rev = "<commit>" }
```

In the monorepo it's a path dependency (`path = "../vlatproto"`), and each
public export pins the matching commit here.

Features:

- `test-clock`: TEST ONLY, `tid::set_test_skew_us`.

Metrics go to prometheus's default registry, so a server's `/metrics`
picks them up. Their names keep the `vlpds_` prefix: dashboards and alerts
of both servers read them. A server that records why it exited hands
`crypto::set_fail_stop_exit` its exit function at startup.

## Working on it

```sh
just check   # every target
just test    # its tests
just ci      # fmt, the private-name scan, check, clippy, test
```

A change here can break vlsync, vlpds or vlRelay: in the monorepo, run
vlsync's `just check-users` before committing.

## License

MIT
