# EasyCA - Certificate Authority Management System

## O projektu

EasyCA je web aplikacija za upravljanje Certificate Authority (CA) infrastrukturom. Omogućava kreiranje Root CA, Intermediate CA, izdavanje server i client sertifikata, revokaciju, export u različitim formatima i još mnogo toga.

## Tehnologije

### Backend
- **Go 1.22** - programski jezik
- **Gin** - web framework
- **SQLite** - baza podataka
- **x509** - Go standardna biblioteka za rad sa sertifikatima
- **go-pkcs12** - biblioteka za PKCS12 export

### Frontend
- **React 18** - UI framework
- **TypeScript** - tipiziran JavaScript
- **Vite** - build tool
- **React Router** - routing

### Infrastruktura
- **Docker** - kontejnerizacija
- **Docker Compose** - orkestracija
- **Nginx** - reverse proxy za frontend

## Struktura projekta

```
EasyCA/
├── backend/
│   ├── cmd/server/
│   │   └── main.go              # Entry point
│   ├── internal/
│   │   ├── api/
│   │   │   └── handler.go       # HTTP handleri
│   │   ├── auth/
│   │   │   └── auth.go          # JWT auth, bcrypt password hashing
│   │   ├── ca/
│   │   │   └── ca.go            # CA operacije (kreiranje, potpisivanje)
│   │   ├── middleware/
│   │   │   ├── auth.go          # Auth & RBAC middleware
│   │   │   ├── metrics.go       # Prometheus metrics middleware
│   │   │   └── ratelimit.go     # Rate limiting middleware
│   │   ├── models/
│   │   │   └── models.go        # Data modeli
│   │   └── storage/
│   │       └── database.go      # SQLite storage layer
│   └── go.mod
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx    # Početna strana sa statistikama
│   │   │   ├── CAs.tsx          # Upravljanje CA
│   │   │   ├── Certificates.tsx # Upravljanje sertifikatima (bulk, auto-renew)
│   │   │   ├── CSRs.tsx         # Certificate Signing Requests
│   │   │   ├── Templates.tsx    # Certificate Templates
│   │   │   ├── Tools.tsx        # Konverzije i import
│   │   │   ├── Learn.tsx        # Edukativni sadržaj
│   │   │   ├── AuditLog.tsx     # Audit log pregled
│   │   │   ├── Login.tsx        # Login/Register stranica
│   │   │   ├── Users.tsx        # User management (admin)
│   │   │   └── Settings.tsx     # SMTP, notifikacije, backup
│   │   ├── App.tsx              # Glavna komponenta + routing
│   │   ├── main.tsx             # Entry point
│   │   └── index.css            # Stilovi (light + dark tema)
│   ├── package.json
│   ├── vite.config.ts
│   └── index.html
├── docker/
│   ├── Dockerfile.backend       # Multi-stage Go build
│   ├── Dockerfile.frontend      # Multi-stage Node build + Nginx
│   └── nginx.conf               # Nginx konfiguracija
├── docker-compose.yml           # Orkestracija servisa
├── .env.example                 # Primer environment varijabli
├── .gitignore
└── PROJECT.md                   # Ovaj fajl
```

## Funkcionalnosti

### CA Management
- Kreiranje Root CA sa konfigurisanim parametrima (CN, Organization, Country, validnost)
- Kreiranje Intermediate CA potpisanog od strane parent CA
- Download CA sertifikata (PEM, DER, CRT format)
- Download CA chain-a

### Certificate Management
- Izdavanje server sertifikata (sa DNS names i IP addresses)
- Izdavanje client sertifikata
- Revokacija sertifikata
- Export u različitim formatima:
  - PEM
  - DER
  - Chain (cert + CA lanac)
  - PKCS12 (.p12)

### Tools
- Konverzija između PEM i DER formata
- Import postojećih sertifikata

### PKI Services
- CRL (Certificate Revocation List) endpoint
- Audit logging svih operacija

### UI Features
- Dark/Light tema sa automatskim detektovanjem sistema
- Responsive dizajn
- Edukativna "Learn" sekcija

## API Endpoints

### CA
```
POST /api/ca/root              - Kreiraj Root CA
POST /api/ca/intermediate      - Kreiraj Intermediate CA
GET  /api/ca                   - Lista svih CA
GET  /api/ca/:id               - Detalji CA
GET  /api/ca/:id/download      - Download CA (format=pem|der|crt)
GET  /api/ca/:id/chain         - Download CA chain
```

### Certificates
```
POST /api/certificates         - Izdaj sertifikat
POST /api/certificates/import  - Import sertifikata
GET  /api/certificates         - Lista sertifikata
GET  /api/certificates/:id     - Detalji sertifikata
POST /api/certificates/:id/revoke     - Revokacija
GET  /api/certificates/:id/download   - Download (format=pem|der)
GET  /api/certificates/:id/chain      - Download sa CA chain-om
POST /api/certificates/:id/export/pkcs12 - Export kao PKCS12
```

### Authentication
```
POST /api/auth/login           - Login (vraća JWT token)
POST /api/auth/register        - Registracija (admin only posle prvog korisnika)
GET  /api/auth/check           - Provera auth statusa
GET  /api/auth/me              - Trenutni korisnik
POST /api/auth/change-password - Promena lozinke
```

### User Management (admin only)
```
GET  /api/users                - Lista korisnika
PUT  /api/users/:id            - Ažuriranje korisnika (role, active)
DELETE /api/users/:id          - Brisanje korisnika
```

### Templates
```
POST /api/templates            - Kreiranje šablona
GET  /api/templates            - Lista šablona
GET  /api/templates/:id        - Detalji šablona
PUT  /api/templates/:id        - Ažuriranje šablona
DELETE /api/templates/:id      - Brisanje šablona
```

### Bulk Operations
```
POST /api/certificates/bulk/revoke  - Bulk revokacija
POST /api/certificates/bulk/export  - Bulk export
POST /api/certificates/bulk/delete  - Bulk brisanje (admin only)
```

### Auto-Renewal
```
POST /api/certificates/:id/auto-renew - Toggle auto-renewal
GET  /api/certificates/:id/auto-renew - Status auto-renewal
```

### Tools & PKI
```
POST /api/convert              - Konverzija formata
GET  /api/audit                - Audit log
GET  /crl/:ca_id               - CRL za CA
POST /ocsp/:ca_id              - OCSP responder
GET  /metrics                  - Prometheus metrike
GET  /health                   - Health check
```

## Pokretanje

### Preduslovi
- Docker
- Docker Compose

### Koraci

1. Kloniraj repozitorijum:
```bash
git clone https://github.com/your-username/EasyCA.git
cd EasyCA
```

2. (Opciono) Podesi encryption key:
```bash
cp .env.example .env
# Edituj .env i postavi CA_ENCRYPTION_KEY
```

3. Pokreni:
```bash
docker compose up --build
```

4. Otvori browser:
```
http://localhost:9988
```

### Portovi
- **9988** - Frontend (Nginx)
- **8444** - Backend API (mapiran sa internog 8443)

## Bezbednost

### Privatni ključevi
- CA privatni ključevi se enkriptuju AES-256-GCM pre čuvanja u bazi
- Encryption key se čita iz `CA_ENCRYPTION_KEY` environment varijable
- Privatni ključevi izdatih sertifikata se NE čuvaju - moraju se sačuvati pri kreiranju

### Preporuke za produkciju
- Generisati siguran encryption key: `openssl rand -base64 32`
- Koristiti HTTPS za frontend
- Ograničiti pristup API-ju
- Redovno backup-ovati SQLite bazu
- Razmotriti HSM za čuvanje Root CA ključa

## Baza podataka

SQLite baza sa tri tabele:

### certificate_authorities
```sql
CREATE TABLE certificate_authorities (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,           -- 'root' | 'intermediate'
    parent_id TEXT,
    certificate BLOB NOT NULL,
    private_key_encrypted BLOB NOT NULL,
    not_before DATETIME,
    not_after DATETIME,
    created_at DATETIME
);
```

### certificates
```sql
CREATE TABLE certificates (
    id TEXT PRIMARY KEY,
    serial_number TEXT UNIQUE NOT NULL,
    ca_id TEXT,
    common_name TEXT NOT NULL,
    type TEXT NOT NULL,           -- 'server' | 'client'
    certificate BLOB NOT NULL,
    not_before DATETIME,
    not_after DATETIME,
    revoked_at DATETIME,
    revocation_reason TEXT,
    created_at DATETIME
);
```

### audit_log
```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME,
    action TEXT NOT NULL,
    entity_type TEXT,
    entity_id TEXT,
    user_id TEXT,
    details TEXT
);
```

## Razvoj

### Lokalni razvoj bez Dockera

Backend (zahteva Go 1.22+):
```bash
cd backend
go mod tidy
CA_ENCRYPTION_KEY=dev-key go run ./cmd/server
```

Frontend (zahteva Node 20+):
```bash
cd frontend
npm install
npm run dev
```

## TODO / Buduće funkcionalnosti

- [x] OCSP responder - `POST /ocsp/:ca_id`
- [x] ACME protokol - `/acme/directory`, account, order, authz, challenge, finalize
- [x] Auto-renewal sertifikata - automatski scheduler 30 dana pre isteka
- [x] User authentication - JWT, login/register, default admin (admin/admin123)
- [x] Role-based access control - admin/operator/viewer sa per-route permisijama
- [x] Certificate templates - CRUD + frontend UI + "Use Template"
- [x] Email notifikacije za istek/izdavanje/revokaciju sertifikata
- [x] Bulk operacije - bulk revoke/export/delete
- [x] API rate limiting - 120 req/min po IP, burst 30
- [x] Metrics/monitoring - Prometheus format na `/metrics`

## Licenca

MIT
