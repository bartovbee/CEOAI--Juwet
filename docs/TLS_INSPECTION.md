# TLS inspection and HTTPS cache

This document explains how to enable TLS inspection (HTTPS interception) for CEOAI Juwet so the proxy can cache HTTPS responses. Use this only on devices and networks you control — installing a local Certificate Authority (CA) and intercepting TLS traffic carries significant security and privacy risks.

## Quick summary

- TLS inspection is opt-in. Enable it via the dashboard API: `POST /api/config` with `{"tlsInspectionEnabled": true}`.
- When you enable inspection without specifying ports, the server will default to intercepting port 443 (`tlsInspectionPorts: [443]`).
- After enabling, download the local CA PEM from `GET /api/tls/ca.pem` and install it into the client trust store so browsers will accept intercepted certificates.

## Enable TLS inspection (server)

1. Start CEOAI Juwet and open the dashboard (`http://127.0.0.1:8787`).
2. Enable inspection (example using curl):

```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"tlsInspectionEnabled": true}' \
  http://127.0.0.1:8787/api/config
```

If you do not provide `tlsInspectionPorts`, the server will automatically set `tlsInspectionPorts: [443]`.

## Download the CA

```bash
curl -sS http://127.0.0.1:8787/api/tls/ca.pem -o CEOAI-Juwet-Inspection-CA.pem
```

## Install the CA (examples)

Windows (PowerShell + certutil):

```powershell
# Import to LocalMachine Trusted Root (requires admin)
certutil -addstore -f "Root" .\CEOAI-Juwet-Inspection-CA.pem
# Or for current user (no admin):
certutil -user -addstore "Root" .\CEOAI-Juwet-Inspection-CA.pem
```

macOS (require admin):

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain CEOAI-Juwet-Inspection-CA.pem
```

Debian/Ubuntu (system-wide):

```bash
sudo cp CEOAI-Juwet-Inspection-CA.pem /usr/local/share/ca-certificates/ceoai-juwet.crt
sudo update-ca-certificates
```

Firefox (profile-specific or preferences):
- Import certificate via Preferences → Privacy & Security → View Certificates → Authorities.

## Configure clients to use the proxy

Set the HTTP and HTTPS proxy to `http://<server-ip>:8080` in the browser or OS network settings so both HTTP and HTTPS requests go through CEOAI Juwet.

## Testing

After installing the CA and configuring the client to use the proxy, visit an HTTPS site through the proxy. The proxy should intercept the TLS handshake and the dashboard tests should show HTTPS MISS/HIT behavior when the site is cacheable.

## Security notes

- Only enable TLS inspection on networks and devices you manage and with explicit consent.
- Do not distribute the CA outside your controlled environment.
- If you suspect the CA or private key has been leaked, rotate the CA by removing the files under the app data `tls` directory and re-enable inspection so the new CA is generated.
