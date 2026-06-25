# dav-office-portal

A thin Rust web portal that gives users a browser-based file manager backed by
[Stalwart Mail Server](https://stalw.art/) WebDAV, with in-browser editing of
`.docx` / `.xlsx` / `.pptx` via [OnlyOffice Document Server](https://www.onlyoffice.com/).

Authentication is OIDC against Stalwart (the same flow the webmail uses).
The portal proxies WebDAV operations to OnlyOffice on the user's behalf and
signs short-lived JWTs so OnlyOffice can call back to fetch and save files.

## Build

```bash
cargo build --release
```

Or via Docker:

```bash
./build.sh   # builds and pushes to the configured registry
```

## Configuration

Environment variables (see `src/config.rs` for the canonical list):

| Var | Default | Purpose |
|---|---|---|
| `BIND_ADDR` | `0.0.0.0:3000` | Listen address (public) |
| `METRICS_ADDR` | `0.0.0.0:9090` | Listen address (Prometheus + health) |
| `PUBLIC_BASE_URL` | (required) | Origin the browser uses to reach the portal (e.g. `https://office.example.com`) |
| `OIDC_ISSUER` | `https://auth.example.com` | OIDC provider |
| `OIDC_CLIENT_ID` | `office-portal` | OIDC client id |
| `OIDC_CLIENT_SECRET` | (required) | OIDC client secret |
| `OO_DOCUMENT_SERVER_URL` | (required) | OnlyOffice Document Server origin (browser-side) |
| `OO_JWT_SECRET` | (required) | Shared JWT secret for OnlyOffice editor configs |
| `FILE_JWT_KEY` | (required) | HS256 key for portal-signed file-access JWTs |
| `SESSION_KEY` | (required) | 32-byte key for encrypted session cookie |
| `DAV_BASE_URL_TEMPLATE` | `https://dav.{domain}` | WebDAV base URL; `{domain}` replaced with the user's email domain |

## Tests

```bash
cargo test            # host-side unit tests
./test.sh             # docker-buildx test target (matches CI)
```

## License

MIT — see [LICENSE](./LICENSE).
