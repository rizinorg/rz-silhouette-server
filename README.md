# Rizin Silhouette Server

This server provides signatures, symbols, and hints to the [rz-silhouette](https://github.com/rizinorg/rz-silhouette) plugin for Rizin.

## Usage

1. Build the https://github.com/rizinorg/rz-silhouette-server and install https://github.com/rizinorg/rz-silhouette
2. Run `rz-silhouette-server -c config.yaml`
3. Execute `rizin -Qc 'aa ; sil share' /path/to/the/binary.exe`

Ensure that the `rizin` plugin `rz-silhouette` points to the server and that the configured PSK is allowed to upload.

## Protocols

The server provides two protocol paths:

1. Legacy protobuf exact matching
2. Cap'n Proto v2 batched resolve/share, with optional ML assistance

## Storage

The server stores exact-match data in BoltDB. Some clients, based on the configuration, can upload new signatures and hints.

If `ml_service_url` is configured, `ResolveProgram` and `ShareProgram` also forward the normalized program bundle to `ml_service/`. Exact-match BoltDB data remains authoritative.

## Documentation

Documentation is available [here](https://github.com/rizinorg/rz-silhouette/tree/main/docs)