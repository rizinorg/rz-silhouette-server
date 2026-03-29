# Rizin Silhouette Server

This server provides signatures, symbols, and hints to the [rz-silhouette](https://github.com/rizinorg/rz-silhouette) plugin for Rizin.

## Usage

1. Build the https://github.com/rizinorg/rz-silhouette-server and install https://github.com/rizinorg/rz-silhouette
2. Run `rz-silhouette-server -c config.yaml`
3. Execute `rizin -Qc 'aa ; sil share' /path/to/the/binary.exe`

Ensure that the `rizin` plugin `rz-silhouette` points to the server and that the configured PSK is allowed to upload.

## Compilation

Install Go, `capnp`, and `capnpc-go`, then build from a clean checkout:

```sh
go generate ./servicecapnp
go build
```

For local installation, place the resulting `rz-silhouette-server` binary somewhere on your `PATH` or run it from the build directory.

For cross-compilation, generate the bindings on the build host first and then run `go build` with the target `GOOS` and `GOARCH`. Do not run `go generate` under the target environment, because the generator itself must execute on the host machine.

## Protocol

The server provides a Cap'n Proto exact-match resolve/share protocol.

## Storage

The server stores exact-match data in BoltDB. Some clients, based on the configuration, can upload new signatures and hints.

## Security

Cap'n Proto does not encrypt traffic. If you expose the raw TCP port, the PSK is still sent in clear text. Set `capnp_require_tls: true` and use the TLS listener for protected deployments.

## Documentation

Documentation is available [here](https://github.com/rizinorg/rz-silhouette/tree/main/docs)
