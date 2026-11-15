# cloudflare-sts-sdk

The Rust SDK for the broker's HTTP API. The API is written in
[TypeSpec](https://typespec.io), in
[`openapi/sts/v1/stsv1.tsp`](openapi/sts/v1/stsv1.tsp),
which compiles to the OpenAPI document
[`stsv1.yaml`](openapi/sts/v1/stsv1.yaml) beside it.
`build.rs` generates the SDK from the document with
[openapi-to-rust](https://github.com/gpu-cli/openapi-to-rust). The health
endpoints aren't part of it: they're hand-written, in
`src/service/handler.rs`, mounted into `v1` beside the generated code.

The document is checked in, so a Rust build needs no Node; none of the Rust is.
Edit the `.tsp`, then compile it:

```sh
cd openapi
nix develop -c npm ci             # once
nix develop -c npm run generate   # after editing the .tsp
```

CI compiles it again and fails if the document differs from the one checked in.

| Feature | |
|---|---|
| (always) | the types: requests, responses, the authorization server metadata (RFC 8414), OAuth errors, with `Error::new`. The health endpoints' paths, `HEALTH_LIVE_PATH` and `HEALTH_READY_PATH`. |
| `server` | A trait per tag, `TokenServiceApi` (the exchange and revocation) and `DiscoveryServiceApi` (the metadata), a response enum per operation, and an axum router per trait, `token_service_api_router` and `discovery_service_api_router`, that checks each request against the spec before it reaches a handler. `HealthHandler`, which answers the health endpoints beside it, `/health/live` and `/health/ready`: ready only while every `HealthCheck` given to `readiness` passes, `503` otherwise. |
| `client` | `HttpClient`, a method per operation, and `HealthClient`, which asks the health endpoints. |

Bodies are form-encoded (`application/x-www-form-urlencoded`), as RFC 8693 and
RFC 7009 have it, and at most 16 KiB. The routers refuse anything else as
`application/problem+json`: another content type with `415`, a larger body with
`413`, and one that doesn't fit the spec with `400` or `422`. The broker answers
all of them as OAuth's `400` `invalid_request`.
