# Visitor app (user-vpn)

Public site that silently records each visit (IP, connection timing, browser/device
fingerprint, optional location) into the shared PostgreSQL database. The admin app
(`../final-vpn`) reads the same database and shows similarity and VPN likelihood.

## Run locally

    cp .env.example .env.local   # fill in DATABASE_URL
    npm install
    npm run dev -- -p 3001

## Deploy

Deploy as its own project (root directory `user-vpn`; build `npm run build`).
Set the variables from `.env.example` in the host's environment settings, not in files.

- `DATABASE_URL` must be the same database the admin app uses.
- `FINGERPRINT_HMAC_SECRET` must equal the admin app's value.
- `TRUSTED_PROXY_PROVIDER` must match the host, or visitor IPs are not trusted.

Visitors never see a VPN verdict; it is stored for the admin dashboard only.
