# Rizin Silhouette Server

This server provides signatures, symbols, and hints to the [rz-silhouette](https://github.com/rizinorg/rz-silhouette) plugin for Rizin.

## Usage

1. Run `go generate ./servicecapnp` on a clean checkout to regenerate `service.capnp.go` (requires `capnp` and `capnpc-go` on `PATH`)
2. Build the https://github.com/rizinorg/rz-silhouette-server and install https://github.com/rizinorg/rz-silhouette
3. Run `rz-silhouette-server -c config.yaml`
4. Execute `rizin -Qc 'aa ; sil share' /path/to/the/binary.exe`

Ensure that the `rizin` plugin `rz-silhouette` points to the server and that the configured PSK is allowed to upload.

## Protocols

The server provides two protocol paths:

1. Legacy protobuf exact matching
2. Cap'n Proto v2 batched resolve/share, with optional ML assistance

## Storage

The server stores exact-match data in BoltDB. Some clients, based on the configuration, can upload new signatures and hints.

If `ml_service_url` is configured, `ResolveProgram` and `ShareProgram` also forward the normalized program bundle to `ml_service/`. Exact-match BoltDB data remains authoritative.
If `ml_service_url` is empty, the server stays exact-match only and no Python runtime is required.

## ML Sidecar

The KEENHash service is an optional sidecar. Create a virtual environment, install `ml_service/requirements.txt`, then run the Python service separately and point `ml_service_url` at it. The Go server does not import or build the Python stack.

## Security

Cap'n Proto v2 does not encrypt traffic. If you expose the raw TCP port, the PSK is still sent in clear text. Set `capnp_require_tls: true` and use the TLS listener for protected deployments.

## Documentation

Documentation is available [here](https://github.com/rizinorg/rz-silhouette/tree/main/docs)
