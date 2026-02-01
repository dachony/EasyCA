# EasyCA

A self-hosted Certificate Authority management system with a modern web interface.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)

## Features

- **CA Management**: Create Root and Intermediate Certificate Authorities
- **Certificate Issuance**: Issue server and client certificates with customizable subject fields
- **CSR Support**: Generate, import, and sign Certificate Signing Requests
- **Multiple Export Formats**: PEM, DER, PKCS12, certificate chains
- **Certificate Revocation**: Revoke certificates with CRL generation
- **SMTP Notifications**: Email alerts for certificate expiration
- **Backup & Restore**: Encrypted backup export/import for disaster recovery
- **Audit Logging**: Track all CA operations
- **Dark/Light Theme**: Modern responsive UI

## Quick Start

### Prerequisites
- Docker
- Docker Compose

### Installation

```bash
git clone https://github.com/your-username/EasyCA.git
cd EasyCA
docker compose up -d
```

Open your browser at `http://localhost:9988`

### Configuration

Create a `.env` file for custom settings:

```bash
# Generate a secure encryption key
CA_ENCRYPTION_KEY=$(openssl rand -base64 32)
```

## Architecture

```
EasyCA/
├── backend/           # Go API server
│   ├── cmd/server/    # Application entry point
│   └── internal/      # Business logic
│       ├── api/       # HTTP handlers
│       ├── ca/        # Certificate operations
│       ├── storage/   # SQLite database
│       └── smtp/      # Email notifications
├── frontend/          # React SPA
│   └── src/
│       └── pages/     # UI components
└── docker/            # Container configs
```

## API Endpoints

### Certificate Authorities
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/ca/root` | Create Root CA |
| POST | `/api/ca/intermediate` | Create Intermediate CA |
| GET | `/api/ca` | List all CAs |
| GET | `/api/ca/:id/download` | Download CA certificate |
| GET | `/api/ca/:id/chain` | Download CA chain |

### Certificates
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/certificates` | Issue certificate |
| GET | `/api/certificates` | List certificates |
| POST | `/api/certificates/:id/revoke` | Revoke certificate |
| GET | `/api/certificates/:id/download` | Download certificate |
| POST | `/api/certificates/:id/export/pkcs12` | Export as PKCS12 |

### CSR Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/csr/generate` | Generate new CSR |
| POST | `/api/csr/import` | Import existing CSR |
| POST | `/api/csr/:id/sign` | Sign CSR with CA |

### Settings
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET/POST | `/api/settings/smtp` | SMTP configuration |
| GET/POST | `/api/settings/notifications` | Notification settings |
| POST | `/api/backup/export` | Export encrypted backup |
| POST | `/api/backup/import` | Import backup |

## Security

- CA private keys are encrypted with AES-256-GCM before storage
- Backup files are encrypted with user-provided password using PBKDF2 key derivation
- Certificate private keys are never stored - save them immediately after creation

### Production Recommendations

- Use a strong `CA_ENCRYPTION_KEY` (generate with `openssl rand -base64 32`)
- Enable HTTPS for the frontend
- Restrict API access with firewall rules
- Regular database backups
- Consider HSM for Root CA key storage

## Development

### Backend (Go 1.22+)
```bash
cd backend
go mod tidy
CA_ENCRYPTION_KEY=dev-key go run ./cmd/server
```

### Frontend (Node 20+)
```bash
cd frontend
npm install
npm run dev
```

## Screenshots

### Dashboard
View CA hierarchy, certificate statistics, and expiration alerts.

### Certificate Management
Issue, revoke, and export certificates in multiple formats.

### Settings
Configure SMTP notifications and manage backups.

## License

MIT License - see [LICENSE](LICENSE) file for details.
