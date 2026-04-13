# ServerStorage

Single-user Lua script hosting dashboard for personal Roblox development.

## What it does

- Password-protected dashboard
- Stores scripts locally on the server
- Generates per-script raw URLs with secret tokens
- Lets you rotate a script token if a link leaks
- Tracks successful raw requests

## Run it

```powershell
node server.js
```

Open `http://127.0.0.1:3000`.

## First setup

On first launch, create an owner password. The app stores only a password hash in `data/config.json`.

## Deployment notes

- Put it behind HTTPS if you expose it on the internet.
- Set `APP_URL` to your public domain before deploying.
- Keep the `data/` folder private.
- Treat every raw URL like a secret because the token in the query string grants access.
