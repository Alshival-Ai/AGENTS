# Alshival.Ai Cloud Hosting Guidelines

These notes are for new demo apps hosted on our Raspberry Pi. We use nginx as the public entrypoint and systemd to run services.

## Ports

- Avoid standard ports for app processes (e.g., 80, 443, 8080, 8000, 5173).
- Pick ports in a reserved range and keep frontend/backend adjacent.
  - Range: 5200-5399 (e.g., frontend 5210, backend 5211).
  - If already used, choose the next open pair.
- Check currently used ports before choosing:
  - `ss -tulpen`
- Record port assignments in the app's `README.md`.

## nginx (public -> internal ports)

- nginx should listen on 80/443 and proxy to app ports.
- Use a per-app server block with a subdomain, e.g. `eyefinityML.alshival.cloud`.
- Example structure:
  - `/etc/nginx/sites-available/<app>`
  - `/etc/nginx/sites-enabled/<app>` (symlink)
- Ensure both `http` and `https` are handled as needed. Use Certbot to obtain a certificate using the email "support@alshival.ai".

## systemd (run the app)

- Create a per-app systemd service for the frontend and backend.
- Use a stable working directory and explicit ports.
- Example locations:
  - `/etc/systemd/system/<app>-frontend.service`
  - `/etc/systemd/system/<app>-backend.service`
- After changes:
  - `sudo systemctl daemon-reload`
  - `sudo systemctl enable --now <service>`
