# Vendored Tetragon API

`v1.8.0/api/v1/tetragon/` is the active wire contract used by `src/collectors/tetragon-proto.js`. It was copied from official Cilium Tetragon tag `v1.8.0` (release commit `a5a6678`). The v1.7.1 sources remain for the sealed SR-GRPC-001 historical benchmark artifacts; they are not loaded by the runtime.

Upstream: [Cilium Tetragon v1.8.0 API](https://github.com/cilium/tetragon/tree/v1.8.0/api/v1/tetragon)  
Release: [v1.8.0](https://github.com/cilium/tetragon/releases/tag/v1.8.0)  
License: Apache-2.0; see [`LICENSE`](LICENSE).

SHA-256 checksums for the active v1.8.0 source files:

| File | SHA-256 |
|---|---|
| `bpf.proto` | `b09c8b5ba2f0c6430bfbbed95ec3b6251f40b07199258ebcf73212c2406685c21` |
| `capabilities.proto` | `49057d368aec5f36e0007e8fd1654524cdf049afe6b1db57af9916bca6edfd25` |
| `events.proto` | `0f856aae2dd9862a870782542633f698fe392d6f5dd17ef496460036b17580a1` |
| `sensors.proto` | `3aea576e97e773418d80bc53ef9eb24600c2fb69c644c57b3ad27b01c139713b` |
| `tetragon.proto` | `be39aab833f5e70e8f84d9147638f6059f296f1fe22de253108768566517431b` |

The collector accepts only `v1.8.0` (with or without the leading `v`) and checks `GetVersion` before opening its event stream. In the protobuf diff, the EventType numbers and event oneof fields used by this collector are unchanged. v1.8.0 adds fields and RPCs in the broader API; the normalizer continues to support only process execution and exit plus rate-limit telemetry, retaining other native event families as unsupported evidence.

The v1.7.1 tree is retained as historical benchmark input. Its checksums are the ones recorded in the SR-GRPC-001 sealed result manifests; do not treat those artifacts as evidence for the active v1.8.0 runtime pin.
