# client-fyne

Early native desktop client using Fyne.

## Current baseline
- Connect/authenticate to a server with Ed25519 identity key
- Send signed direct messages (`send`)
- Receive and display server events/messages
- Local identity key load/create at a file path

## Run
```bash
go run ./client-fyne
```

Default values:
- server: `127.0.0.1:9101`
- key file: `~/.goaccord/ed25519_key.json`

This is an initial scaffold. Feature parity with `client-web` / `client-tui` is not implemented yet.
