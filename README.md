# Rizin Silhouette Server

This server is used to provide signatures using the [rz-silhouette](https://github.com/rizinorg/rz-silhouette) plugin for rizin.

## Generating signatures

1. Build the https://github.com/rizinorg/rz-silhouette-server and install https://github.com/rizinorg/rz-silhouette
2. Run `rz-silhouette-server -c config.yaml`
3. Execute `rizin -Qc 'aa ; sil share' /path/to/the/binary.exe`

Ensure that the `rizin` plugin `rz-silhouette` is configured to point towards the server and that the user can share the info with the server.

## Info the server provides

The server will provide 2 types of info

1. Hints based on the match on the binary section
2. Symbols based on their signatures

## Server behaviour

The server stores the info into databases.
Some clients (based on the configuration) can be allowed to upload new signatures and hints.

## Documentation

Documentation is available [here](https://github.com/rizinorg/rz-silhouette/tree/main/docs)