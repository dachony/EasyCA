package storage

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/dachony/easyca/internal/models"
	_ "github.com/mattn/go-sqlite3"
)

type Database struct {
	db *sql.DB
}

func NewDatabase(dbPath string) (*Database, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	database := &Database{db: db}
	if err := database.migrate(); err != nil {
		return nil, err
	}

	return database, nil
}

func (d *Database) Close() error {
	return d.db.Close()
}

func (d *Database) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS certificate_authorities (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		type TEXT NOT NULL,
		parent_id TEXT REFERENCES certificate_authorities(id),
		certificate BLOB NOT NULL,
		private_key_encrypted BLOB NOT NULL,
		not_before DATETIME,
		not_after DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS certificates (
		id TEXT PRIMARY KEY,
		serial_number TEXT UNIQUE NOT NULL,
		ca_id TEXT REFERENCES certificate_authorities(id),
		common_name TEXT NOT NULL,
		type TEXT NOT NULL,
		certificate BLOB NOT NULL,
		not_before DATETIME,
		not_after DATETIME,
		revoked_at DATETIME,
		revocation_reason TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		action TEXT NOT NULL,
		entity_type TEXT,
		entity_id TEXT,
		user_id TEXT,
		details TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_certificates_ca_id ON certificates(ca_id);
	CREATE INDEX IF NOT EXISTS idx_certificates_serial ON certificates(serial_number);
	CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);

	-- CSR table
	CREATE TABLE IF NOT EXISTS certificate_signing_requests (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		csr_pem TEXT NOT NULL,
		common_name TEXT,
		organization TEXT,
		organizational_unit TEXT,
		country TEXT,
		state TEXT,
		locality TEXT,
		street_address TEXT,
		postal_code TEXT,
		email_address TEXT,
		dns_names TEXT,
		ip_addresses TEXT,
		status TEXT DEFAULT 'pending',
		signed_certificate_id TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_csr_status ON certificate_signing_requests(status);

	-- SMTP configuration
	CREATE TABLE IF NOT EXISTS smtp_config (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		host TEXT NOT NULL,
		port INTEGER DEFAULT 587,
		username TEXT,
		password_encrypted BLOB,
		from_address TEXT NOT NULL,
		tls_enabled INTEGER DEFAULT 1,
		enabled INTEGER DEFAULT 0,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Notification recipients
	CREATE TABLE IF NOT EXISTS notification_recipients (
		id TEXT PRIMARY KEY,
		email TEXT NOT NULL,
		certificate_id TEXT,
		ca_id TEXT,
		is_global INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_recipients_global ON notification_recipients(is_global);

	-- Notification settings
	CREATE TABLE IF NOT EXISTS notification_settings (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		expiry_warning_days TEXT DEFAULT '30,14,7',
		notify_on_issuance INTEGER DEFAULT 1,
		notify_on_revocation INTEGER DEFAULT 1
	);

	-- Initialize default notification settings
	INSERT OR IGNORE INTO notification_settings (id, expiry_warning_days, notify_on_issuance, notify_on_revocation)
	VALUES (1, '30,14,7', 1, 1);

	-- Notification log
	CREATE TABLE IF NOT EXISTS notification_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		certificate_id TEXT,
		ca_id TEXT,
		notification_type TEXT NOT NULL,
		recipient_email TEXT NOT NULL,
		days_until_expiry INTEGER,
		sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		status TEXT NOT NULL,
		error_message TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_notification_log_sent ON notification_log(sent_at);

	-- Default settings for CA/certificate creation
	CREATE TABLE IF NOT EXISTS default_settings (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		key_algorithm TEXT DEFAULT 'rsa2048',
		signature_algorithm TEXT DEFAULT 'sha256',
		validity_days_ca INTEGER DEFAULT 3650,
		validity_days_cert INTEGER DEFAULT 365,
		organization TEXT DEFAULT '',
		organizational_unit TEXT DEFAULT '',
		country TEXT DEFAULT '',
		state TEXT DEFAULT '',
		locality TEXT DEFAULT ''
	);

	-- Initialize default settings
	INSERT OR IGNORE INTO default_settings (id, key_algorithm, signature_algorithm, validity_days_ca, validity_days_cert)
	VALUES (1, 'rsa2048', 'sha256', 3650, 365);

	-- Time settings
	CREATE TABLE IF NOT EXISTS time_settings (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		time_source TEXT DEFAULT 'host',
		ntp_server TEXT DEFAULT 'pool.ntp.org',
		timezone TEXT DEFAULT 'UTC',
		manual_time TEXT,
		last_synced_at DATETIME
	);

	-- Initialize time settings
	INSERT OR IGNORE INTO time_settings (id, time_source, ntp_server, timezone)
	VALUES (1, 'host', 'pool.ntp.org', 'UTC');
	`

	_, err := d.db.Exec(schema)
	if err != nil {
		return err
	}

	// Add new columns for organization and dns_names (migrations)
	migrations := []string{
		`ALTER TABLE certificate_authorities ADD COLUMN common_name TEXT`,
		`ALTER TABLE certificate_authorities ADD COLUMN organization TEXT`,
		`ALTER TABLE certificate_authorities ADD COLUMN dns_names TEXT`,
		`ALTER TABLE certificate_authorities ADD COLUMN key_algorithm TEXT`,
		`ALTER TABLE certificate_authorities ADD COLUMN signature_algorithm TEXT`,
		`ALTER TABLE certificates ADD COLUMN organization TEXT`,
		`ALTER TABLE certificates ADD COLUMN dns_names TEXT`,
		`ALTER TABLE certificates ADD COLUMN key_algorithm TEXT`,
		`ALTER TABLE certificates ADD COLUMN signature_algorithm TEXT`,
	}

	for _, m := range migrations {
		d.db.Exec(m) // Ignore errors (column may already exist)
	}

	return nil
}

func (d *Database) CreateCA(ca *models.CertificateAuthority) error {
	dnsNamesJSON, _ := json.Marshal(ca.DNSNames)
	_, err := d.db.Exec(`
		INSERT INTO certificate_authorities
		(id, name, type, parent_id, common_name, organization, dns_names, key_algorithm, signature_algorithm, certificate, private_key_encrypted, not_before, not_after, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ca.ID, ca.Name, ca.Type, ca.ParentID, ca.CommonName, ca.Organization, string(dnsNamesJSON),
		ca.KeyAlgorithm, ca.SignatureAlgorithm, ca.Certificate, ca.PrivateKeyEncrypted, ca.NotBefore, ca.NotAfter, ca.CreatedAt,
	)
	return err
}

func (d *Database) GetCA(id string) (*models.CertificateAuthority, error) {
	ca := &models.CertificateAuthority{}
	var dnsNamesJSON sql.NullString
	var commonName, organization sql.NullString
	var keyAlgorithm, signatureAlgorithm sql.NullString
	err := d.db.QueryRow(`
		SELECT id, name, type, parent_id, common_name, organization, dns_names, key_algorithm, signature_algorithm, certificate, private_key_encrypted, not_before, not_after, created_at
		FROM certificate_authorities WHERE id = ?`, id,
	).Scan(&ca.ID, &ca.Name, &ca.Type, &ca.ParentID, &commonName, &organization, &dnsNamesJSON,
		&keyAlgorithm, &signatureAlgorithm, &ca.Certificate, &ca.PrivateKeyEncrypted, &ca.NotBefore, &ca.NotAfter, &ca.CreatedAt)
	if err != nil {
		return nil, err
	}
	ca.CommonName = commonName.String
	ca.Organization = organization.String
	ca.KeyAlgorithm = models.KeyAlgorithm(keyAlgorithm.String)
	ca.SignatureAlgorithm = models.SignatureAlgorithm(signatureAlgorithm.String)
	if dnsNamesJSON.Valid && dnsNamesJSON.String != "" {
		json.Unmarshal([]byte(dnsNamesJSON.String), &ca.DNSNames)
	}
	return ca, nil
}

func (d *Database) ListCAs() ([]models.CertificateAuthority, error) {
	rows, err := d.db.Query(`
		SELECT id, name, type, parent_id, common_name, organization, dns_names, key_algorithm, signature_algorithm, certificate, not_before, not_after, created_at
		FROM certificate_authorities ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cas []models.CertificateAuthority
	for rows.Next() {
		var ca models.CertificateAuthority
		var dnsNamesJSON sql.NullString
		var commonName, organization sql.NullString
		var keyAlgorithm, signatureAlgorithm sql.NullString
		if err := rows.Scan(&ca.ID, &ca.Name, &ca.Type, &ca.ParentID, &commonName, &organization, &dnsNamesJSON,
			&keyAlgorithm, &signatureAlgorithm, &ca.Certificate, &ca.NotBefore, &ca.NotAfter, &ca.CreatedAt); err != nil {
			return nil, err
		}
		ca.CommonName = commonName.String
		ca.Organization = organization.String
		ca.KeyAlgorithm = models.KeyAlgorithm(keyAlgorithm.String)
		ca.SignatureAlgorithm = models.SignatureAlgorithm(signatureAlgorithm.String)
		if dnsNamesJSON.Valid && dnsNamesJSON.String != "" {
			json.Unmarshal([]byte(dnsNamesJSON.String), &ca.DNSNames)
		}
		cas = append(cas, ca)
	}
	return cas, nil
}

func (d *Database) CreateCertificate(cert *models.Certificate) error {
	dnsNamesJSON, _ := json.Marshal(cert.DNSNames)
	_, err := d.db.Exec(`
		INSERT INTO certificates
		(id, serial_number, ca_id, common_name, organization, dns_names, key_algorithm, signature_algorithm, type, certificate, not_before, not_after, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cert.ID, cert.SerialNumber, cert.CAID, cert.CommonName, cert.Organization, string(dnsNamesJSON),
		cert.KeyAlgorithm, cert.SignatureAlgorithm, cert.Type, cert.Certificate, cert.NotBefore, cert.NotAfter, cert.CreatedAt,
	)
	return err
}

func (d *Database) GetCertificate(id string) (*models.Certificate, error) {
	cert := &models.Certificate{}
	var organization sql.NullString
	var dnsNamesJSON sql.NullString
	var keyAlgorithm, signatureAlgorithm sql.NullString
	err := d.db.QueryRow(`
		SELECT id, serial_number, ca_id, common_name, organization, dns_names, key_algorithm, signature_algorithm, type, certificate,
		       not_before, not_after, revoked_at, revocation_reason, created_at
		FROM certificates WHERE id = ?`, id,
	).Scan(&cert.ID, &cert.SerialNumber, &cert.CAID, &cert.CommonName, &organization, &dnsNamesJSON,
		&keyAlgorithm, &signatureAlgorithm, &cert.Type, &cert.Certificate, &cert.NotBefore, &cert.NotAfter, &cert.RevokedAt,
		&cert.RevocationReason, &cert.CreatedAt)
	if err != nil {
		return nil, err
	}
	cert.Organization = organization.String
	cert.KeyAlgorithm = models.KeyAlgorithm(keyAlgorithm.String)
	cert.SignatureAlgorithm = models.SignatureAlgorithm(signatureAlgorithm.String)
	if dnsNamesJSON.Valid && dnsNamesJSON.String != "" {
		json.Unmarshal([]byte(dnsNamesJSON.String), &cert.DNSNames)
	}
	return cert, nil
}

func (d *Database) ListCertificates() ([]models.Certificate, error) {
	rows, err := d.db.Query(`
		SELECT id, serial_number, ca_id, common_name, organization, dns_names, key_algorithm, signature_algorithm, type, certificate,
		       not_before, not_after, revoked_at, revocation_reason, created_at
		FROM certificates ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []models.Certificate
	for rows.Next() {
		var cert models.Certificate
		var organization sql.NullString
		var dnsNamesJSON sql.NullString
		var keyAlgorithm, signatureAlgorithm sql.NullString
		if err := rows.Scan(&cert.ID, &cert.SerialNumber, &cert.CAID, &cert.CommonName, &organization, &dnsNamesJSON,
			&keyAlgorithm, &signatureAlgorithm, &cert.Type, &cert.Certificate, &cert.NotBefore, &cert.NotAfter,
			&cert.RevokedAt, &cert.RevocationReason, &cert.CreatedAt); err != nil {
			return nil, err
		}
		cert.Organization = organization.String
		cert.KeyAlgorithm = models.KeyAlgorithm(keyAlgorithm.String)
		cert.SignatureAlgorithm = models.SignatureAlgorithm(signatureAlgorithm.String)
		if dnsNamesJSON.Valid && dnsNamesJSON.String != "" {
			json.Unmarshal([]byte(dnsNamesJSON.String), &cert.DNSNames)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func (d *Database) ListCertificatesByCA(caID string) ([]models.Certificate, error) {
	rows, err := d.db.Query(`
		SELECT id, serial_number, ca_id, common_name, organization, dns_names, key_algorithm, signature_algorithm, type, certificate,
		       not_before, not_after, revoked_at, revocation_reason, created_at
		FROM certificates WHERE ca_id = ? ORDER BY created_at DESC`, caID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []models.Certificate
	for rows.Next() {
		var cert models.Certificate
		var organization sql.NullString
		var dnsNamesJSON sql.NullString
		var keyAlgorithm, signatureAlgorithm sql.NullString
		if err := rows.Scan(&cert.ID, &cert.SerialNumber, &cert.CAID, &cert.CommonName, &organization, &dnsNamesJSON,
			&keyAlgorithm, &signatureAlgorithm, &cert.Type, &cert.Certificate, &cert.NotBefore, &cert.NotAfter,
			&cert.RevokedAt, &cert.RevocationReason, &cert.CreatedAt); err != nil {
			return nil, err
		}
		cert.Organization = organization.String
		cert.KeyAlgorithm = models.KeyAlgorithm(keyAlgorithm.String)
		cert.SignatureAlgorithm = models.SignatureAlgorithm(signatureAlgorithm.String)
		if dnsNamesJSON.Valid && dnsNamesJSON.String != "" {
			json.Unmarshal([]byte(dnsNamesJSON.String), &cert.DNSNames)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func (d *Database) RevokeCertificate(id string, reason string) error {
	_, err := d.db.Exec(`
		UPDATE certificates SET revoked_at = ?, revocation_reason = ? WHERE id = ?`,
		time.Now(), reason, id,
	)
	return err
}

func (d *Database) DeleteCertificate(id string) error {
	_, err := d.db.Exec(`DELETE FROM certificates WHERE id = ?`, id)
	return err
}

func (d *Database) GetRevokedCertificates(caID string) ([]models.Certificate, error) {
	rows, err := d.db.Query(`
		SELECT id, serial_number, ca_id, common_name, organization, dns_names, key_algorithm, signature_algorithm, type, certificate,
		       not_before, not_after, revoked_at, revocation_reason, created_at
		FROM certificates WHERE ca_id = ? AND revoked_at IS NOT NULL`, caID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []models.Certificate
	for rows.Next() {
		var cert models.Certificate
		var organization sql.NullString
		var dnsNamesJSON sql.NullString
		var keyAlgorithm, signatureAlgorithm sql.NullString
		if err := rows.Scan(&cert.ID, &cert.SerialNumber, &cert.CAID, &cert.CommonName, &organization, &dnsNamesJSON,
			&keyAlgorithm, &signatureAlgorithm, &cert.Type, &cert.Certificate, &cert.NotBefore, &cert.NotAfter,
			&cert.RevokedAt, &cert.RevocationReason, &cert.CreatedAt); err != nil {
			return nil, err
		}
		cert.Organization = organization.String
		cert.KeyAlgorithm = models.KeyAlgorithm(keyAlgorithm.String)
		cert.SignatureAlgorithm = models.SignatureAlgorithm(signatureAlgorithm.String)
		if dnsNamesJSON.Valid && dnsNamesJSON.String != "" {
			json.Unmarshal([]byte(dnsNamesJSON.String), &cert.DNSNames)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func (d *Database) AddAuditLog(action, entityType, entityID, userID, details string) error {
	_, err := d.db.Exec(`
		INSERT INTO audit_log (action, entity_type, entity_id, user_id, details)
		VALUES (?, ?, ?, ?, ?)`,
		action, entityType, entityID, userID, details,
	)
	return err
}

func (d *Database) GetAuditLogs(limit int) ([]models.AuditLog, error) {
	rows, err := d.db.Query(`
		SELECT id, timestamp, action, entity_type, entity_id, user_id, details
		FROM audit_log ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []models.AuditLog
	for rows.Next() {
		var log models.AuditLog
		if err := rows.Scan(&log.ID, &log.Timestamp, &log.Action, &log.EntityType,
			&log.EntityID, &log.UserID, &log.Details); err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}
	return logs, nil
}

// CSR Methods

func (d *Database) CreateCSR(csr *models.CertificateSigningRequest) error {
	dnsNamesJSON, _ := json.Marshal(csr.DNSNames)
	ipAddressesJSON, _ := json.Marshal(csr.IPAddresses)

	_, err := d.db.Exec(`
		INSERT INTO certificate_signing_requests
		(id, name, csr_pem, common_name, organization, organizational_unit, country, state, locality,
		 street_address, postal_code, email_address, dns_names, ip_addresses, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		csr.ID, csr.Name, csr.CSRPEM, csr.CommonName, csr.Organization, csr.OrganizationalUnit,
		csr.Country, csr.State, csr.Locality, csr.StreetAddress, csr.PostalCode, csr.EmailAddress,
		string(dnsNamesJSON), string(ipAddressesJSON), csr.Status, csr.CreatedAt, csr.UpdatedAt,
	)
	return err
}

func (d *Database) GetCSR(id string) (*models.CertificateSigningRequest, error) {
	csr := &models.CertificateSigningRequest{}
	var dnsNamesJSON, ipAddressesJSON string

	err := d.db.QueryRow(`
		SELECT id, name, csr_pem, common_name, organization, organizational_unit, country, state, locality,
		       street_address, postal_code, email_address, dns_names, ip_addresses, status,
		       signed_certificate_id, created_at, updated_at
		FROM certificate_signing_requests WHERE id = ?`, id,
	).Scan(&csr.ID, &csr.Name, &csr.CSRPEM, &csr.CommonName, &csr.Organization, &csr.OrganizationalUnit,
		&csr.Country, &csr.State, &csr.Locality, &csr.StreetAddress, &csr.PostalCode, &csr.EmailAddress,
		&dnsNamesJSON, &ipAddressesJSON, &csr.Status, &csr.SignedCertificateID, &csr.CreatedAt, &csr.UpdatedAt)

	if err != nil {
		return nil, err
	}

	json.Unmarshal([]byte(dnsNamesJSON), &csr.DNSNames)
	json.Unmarshal([]byte(ipAddressesJSON), &csr.IPAddresses)

	return csr, nil
}

func (d *Database) ListCSRs() ([]models.CertificateSigningRequest, error) {
	rows, err := d.db.Query(`
		SELECT id, name, csr_pem, common_name, organization, organizational_unit, country, state, locality,
		       street_address, postal_code, email_address, dns_names, ip_addresses, status,
		       signed_certificate_id, created_at, updated_at
		FROM certificate_signing_requests ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var csrs []models.CertificateSigningRequest
	for rows.Next() {
		var csr models.CertificateSigningRequest
		var dnsNamesJSON, ipAddressesJSON string

		if err := rows.Scan(&csr.ID, &csr.Name, &csr.CSRPEM, &csr.CommonName, &csr.Organization, &csr.OrganizationalUnit,
			&csr.Country, &csr.State, &csr.Locality, &csr.StreetAddress, &csr.PostalCode, &csr.EmailAddress,
			&dnsNamesJSON, &ipAddressesJSON, &csr.Status, &csr.SignedCertificateID, &csr.CreatedAt, &csr.UpdatedAt); err != nil {
			return nil, err
		}

		json.Unmarshal([]byte(dnsNamesJSON), &csr.DNSNames)
		json.Unmarshal([]byte(ipAddressesJSON), &csr.IPAddresses)

		csrs = append(csrs, csr)
	}
	return csrs, nil
}

func (d *Database) UpdateCSRStatus(id string, status models.CSRStatus, signedCertID *string) error {
	_, err := d.db.Exec(`
		UPDATE certificate_signing_requests
		SET status = ?, signed_certificate_id = ?, updated_at = ?
		WHERE id = ?`,
		status, signedCertID, time.Now(), id,
	)
	return err
}

func (d *Database) DeleteCSR(id string) error {
	_, err := d.db.Exec(`DELETE FROM certificate_signing_requests WHERE id = ?`, id)
	return err
}

// SMTP Config Methods

func (d *Database) GetSMTPConfig() (*models.SMTPConfig, error) {
	config := &models.SMTPConfig{}
	err := d.db.QueryRow(`
		SELECT id, host, port, username, password_encrypted, from_address, tls_enabled, enabled, updated_at
		FROM smtp_config WHERE id = 1`,
	).Scan(&config.ID, &config.Host, &config.Port, &config.Username, &config.PasswordEncrypted,
		&config.FromAddress, &config.TLSEnabled, &config.Enabled, &config.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return config, nil
}

func (d *Database) SaveSMTPConfig(config *models.SMTPConfig) error {
	_, err := d.db.Exec(`
		INSERT INTO smtp_config (id, host, port, username, password_encrypted, from_address, tls_enabled, enabled, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			host = excluded.host,
			port = excluded.port,
			username = excluded.username,
			password_encrypted = excluded.password_encrypted,
			from_address = excluded.from_address,
			tls_enabled = excluded.tls_enabled,
			enabled = excluded.enabled,
			updated_at = excluded.updated_at`,
		config.Host, config.Port, config.Username, config.PasswordEncrypted,
		config.FromAddress, config.TLSEnabled, config.Enabled, time.Now(),
	)
	return err
}

// Notification Recipients Methods

func (d *Database) CreateRecipient(recipient *models.NotificationRecipient) error {
	_, err := d.db.Exec(`
		INSERT INTO notification_recipients (id, email, certificate_id, ca_id, is_global, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		recipient.ID, recipient.Email, recipient.CertificateID, recipient.CAID,
		recipient.IsGlobal, recipient.CreatedAt,
	)
	return err
}

func (d *Database) ListRecipients() ([]models.NotificationRecipient, error) {
	rows, err := d.db.Query(`
		SELECT id, email, certificate_id, ca_id, is_global, created_at
		FROM notification_recipients ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var recipients []models.NotificationRecipient
	for rows.Next() {
		var r models.NotificationRecipient
		if err := rows.Scan(&r.ID, &r.Email, &r.CertificateID, &r.CAID, &r.IsGlobal, &r.CreatedAt); err != nil {
			return nil, err
		}
		recipients = append(recipients, r)
	}
	return recipients, nil
}

func (d *Database) GetRecipientsForCertificate(certID string, caID string) ([]models.NotificationRecipient, error) {
	rows, err := d.db.Query(`
		SELECT id, email, certificate_id, ca_id, is_global, created_at
		FROM notification_recipients
		WHERE is_global = 1 OR certificate_id = ? OR ca_id = ?`, certID, caID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var recipients []models.NotificationRecipient
	for rows.Next() {
		var r models.NotificationRecipient
		if err := rows.Scan(&r.ID, &r.Email, &r.CertificateID, &r.CAID, &r.IsGlobal, &r.CreatedAt); err != nil {
			return nil, err
		}
		recipients = append(recipients, r)
	}
	return recipients, nil
}

func (d *Database) DeleteRecipient(id string) error {
	_, err := d.db.Exec(`DELETE FROM notification_recipients WHERE id = ?`, id)
	return err
}

// Notification Settings Methods

func (d *Database) GetNotificationSettings() (*models.NotificationSettings, error) {
	settings := &models.NotificationSettings{}
	err := d.db.QueryRow(`
		SELECT id, expiry_warning_days, notify_on_issuance, notify_on_revocation
		FROM notification_settings WHERE id = 1`,
	).Scan(&settings.ID, &settings.ExpiryWarningDays, &settings.NotifyOnIssuance, &settings.NotifyOnRevocation)

	if err == sql.ErrNoRows {
		return &models.NotificationSettings{
			ID:                 1,
			ExpiryWarningDays:  "30,14,7",
			NotifyOnIssuance:   true,
			NotifyOnRevocation: true,
		}, nil
	}
	if err != nil {
		return nil, err
	}
	return settings, nil
}

func (d *Database) SaveNotificationSettings(settings *models.NotificationSettings) error {
	_, err := d.db.Exec(`
		INSERT INTO notification_settings (id, expiry_warning_days, notify_on_issuance, notify_on_revocation)
		VALUES (1, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			expiry_warning_days = excluded.expiry_warning_days,
			notify_on_issuance = excluded.notify_on_issuance,
			notify_on_revocation = excluded.notify_on_revocation`,
		settings.ExpiryWarningDays, settings.NotifyOnIssuance, settings.NotifyOnRevocation,
	)
	return err
}

// Default Settings Methods

func (d *Database) GetDefaultSettings() (*models.DefaultSettings, error) {
	settings := &models.DefaultSettings{}
	var keyAlg, sigAlg, org, ou, country, state, locality sql.NullString
	err := d.db.QueryRow(`
		SELECT id, key_algorithm, signature_algorithm, validity_days_ca, validity_days_cert,
		       organization, organizational_unit, country, state, locality
		FROM default_settings WHERE id = 1`,
	).Scan(&settings.ID, &keyAlg, &sigAlg, &settings.ValidityDaysCA, &settings.ValidityDaysCert,
		&org, &ou, &country, &state, &locality)

	if err == sql.ErrNoRows {
		return &models.DefaultSettings{
			ID:                   1,
			KeyAlgorithm:         models.KeyAlgorithmRSA2048,
			SignatureAlgorithm:   models.SignatureAlgorithmSHA256,
			ValidityDaysCA:       3650,
			ValidityDaysCert:     365,
			Organization:         "",
			OrganizationalUnit:   "",
			Country:              "",
			State:                "",
			Locality:             "",
		}, nil
	}
	if err != nil {
		return nil, err
	}

	settings.KeyAlgorithm = models.KeyAlgorithm(keyAlg.String)
	settings.SignatureAlgorithm = models.SignatureAlgorithm(sigAlg.String)
	settings.Organization = org.String
	settings.OrganizationalUnit = ou.String
	settings.Country = country.String
	settings.State = state.String
	settings.Locality = locality.String

	return settings, nil
}

func (d *Database) SaveDefaultSettings(settings *models.DefaultSettings) error {
	_, err := d.db.Exec(`
		INSERT INTO default_settings (id, key_algorithm, signature_algorithm, validity_days_ca, validity_days_cert,
		                              organization, organizational_unit, country, state, locality)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			key_algorithm = excluded.key_algorithm,
			signature_algorithm = excluded.signature_algorithm,
			validity_days_ca = excluded.validity_days_ca,
			validity_days_cert = excluded.validity_days_cert,
			organization = excluded.organization,
			organizational_unit = excluded.organizational_unit,
			country = excluded.country,
			state = excluded.state,
			locality = excluded.locality`,
		settings.KeyAlgorithm, settings.SignatureAlgorithm, settings.ValidityDaysCA, settings.ValidityDaysCert,
		settings.Organization, settings.OrganizationalUnit, settings.Country, settings.State, settings.Locality,
	)
	return err
}

// Time Settings Methods

func (d *Database) GetTimeSettings() (*models.TimeSettings, error) {
	settings := &models.TimeSettings{}
	var timeSource, ntpServer, timezone, manualTime, lastSynced sql.NullString

	err := d.db.QueryRow(`
		SELECT id, time_source, ntp_server, timezone, manual_time, last_synced_at
		FROM time_settings WHERE id = 1`,
	).Scan(&settings.ID, &timeSource, &ntpServer, &timezone, &manualTime, &lastSynced)

	if err == sql.ErrNoRows {
		return &models.TimeSettings{
			ID:         1,
			TimeSource: models.TimeSourceHost,
			NTPServer:  "pool.ntp.org",
			Timezone:   "UTC",
		}, nil
	}
	if err != nil {
		return nil, err
	}

	settings.TimeSource = models.TimeSource(timeSource.String)
	settings.NTPServer = ntpServer.String
	settings.Timezone = timezone.String
	settings.ManualTime = manualTime.String
	settings.LastSyncedAt = lastSynced.String

	return settings, nil
}

func (d *Database) SaveTimeSettings(settings *models.TimeSettings) error {
	_, err := d.db.Exec(`
		INSERT INTO time_settings (id, time_source, ntp_server, timezone, manual_time, last_synced_at)
		VALUES (1, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			time_source = excluded.time_source,
			ntp_server = excluded.ntp_server,
			timezone = excluded.timezone,
			manual_time = excluded.manual_time,
			last_synced_at = excluded.last_synced_at`,
		settings.TimeSource, settings.NTPServer, settings.Timezone, settings.ManualTime, settings.LastSyncedAt,
	)
	return err
}

// Notification Log Methods

func (d *Database) AddNotificationLog(log *models.NotificationLog) error {
	_, err := d.db.Exec(`
		INSERT INTO notification_log (certificate_id, ca_id, notification_type, recipient_email, days_until_expiry, sent_at, status, error_message)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		log.CertificateID, log.CAID, log.NotificationType, log.RecipientEmail,
		log.DaysUntilExpiry, log.SentAt, log.Status, log.ErrorMessage,
	)
	return err
}

func (d *Database) GetNotificationLogs(limit int) ([]models.NotificationLog, error) {
	rows, err := d.db.Query(`
		SELECT id, certificate_id, ca_id, notification_type, recipient_email, days_until_expiry, sent_at, status, error_message
		FROM notification_log ORDER BY sent_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []models.NotificationLog
	for rows.Next() {
		var log models.NotificationLog
		if err := rows.Scan(&log.ID, &log.CertificateID, &log.CAID, &log.NotificationType,
			&log.RecipientEmail, &log.DaysUntilExpiry, &log.SentAt, &log.Status, &log.ErrorMessage); err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}
	return logs, nil
}

// Helper method for scheduler - get certificates expiring within days
func (d *Database) GetExpiringCertificates(days int) ([]models.Certificate, error) {
	rows, err := d.db.Query(`
		SELECT id, serial_number, ca_id, common_name, organization, dns_names, key_algorithm, signature_algorithm, type, certificate,
		       not_before, not_after, revoked_at, revocation_reason, created_at
		FROM certificates
		WHERE revoked_at IS NULL
		  AND not_after <= datetime('now', '+' || ? || ' days')
		  AND not_after > datetime('now')
		ORDER BY not_after ASC`, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []models.Certificate
	for rows.Next() {
		var cert models.Certificate
		var organization sql.NullString
		var dnsNamesJSON sql.NullString
		var keyAlgorithm, signatureAlgorithm sql.NullString
		if err := rows.Scan(&cert.ID, &cert.SerialNumber, &cert.CAID, &cert.CommonName, &organization, &dnsNamesJSON,
			&keyAlgorithm, &signatureAlgorithm, &cert.Type, &cert.Certificate, &cert.NotBefore, &cert.NotAfter,
			&cert.RevokedAt, &cert.RevocationReason, &cert.CreatedAt); err != nil {
			return nil, err
		}
		cert.Organization = organization.String
		cert.KeyAlgorithm = models.KeyAlgorithm(keyAlgorithm.String)
		cert.SignatureAlgorithm = models.SignatureAlgorithm(signatureAlgorithm.String)
		if dnsNamesJSON.Valid && dnsNamesJSON.String != "" {
			json.Unmarshal([]byte(dnsNamesJSON.String), &cert.DNSNames)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// Get expiring CAs
func (d *Database) GetExpiringCAs(days int) ([]models.CertificateAuthority, error) {
	rows, err := d.db.Query(`
		SELECT id, name, type, parent_id, common_name, organization, dns_names, key_algorithm, signature_algorithm, certificate, not_before, not_after, created_at
		FROM certificate_authorities
		WHERE not_after <= datetime('now', '+' || ? || ' days')
		  AND not_after > datetime('now')
		ORDER BY not_after ASC`, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cas []models.CertificateAuthority
	for rows.Next() {
		var ca models.CertificateAuthority
		var dnsNamesJSON sql.NullString
		var commonName, organization sql.NullString
		var keyAlgorithm, signatureAlgorithm sql.NullString
		if err := rows.Scan(&ca.ID, &ca.Name, &ca.Type, &ca.ParentID, &commonName, &organization, &dnsNamesJSON,
			&keyAlgorithm, &signatureAlgorithm, &ca.Certificate, &ca.NotBefore, &ca.NotAfter, &ca.CreatedAt); err != nil {
			return nil, err
		}
		ca.CommonName = commonName.String
		ca.Organization = organization.String
		ca.KeyAlgorithm = models.KeyAlgorithm(keyAlgorithm.String)
		ca.SignatureAlgorithm = models.SignatureAlgorithm(signatureAlgorithm.String)
		if dnsNamesJSON.Valid && dnsNamesJSON.String != "" {
			json.Unmarshal([]byte(dnsNamesJSON.String), &ca.DNSNames)
		}
		cas = append(cas, ca)
	}
	return cas, nil
}

// GetAllCAsWithKeys returns all CAs with their encrypted private keys
func (d *Database) GetAllCAsWithKeys() ([]models.CertificateAuthority, error) {
	rows, err := d.db.Query(`
		SELECT id, name, type, parent_id, common_name, organization, dns_names, key_algorithm, signature_algorithm,
		       certificate, private_key_encrypted, not_before, not_after, created_at
		FROM certificate_authorities ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cas []models.CertificateAuthority
	for rows.Next() {
		var ca models.CertificateAuthority
		var parentID sql.NullString
		var commonName, organization sql.NullString
		var dnsNamesJSON sql.NullString
		var keyAlgorithm, signatureAlgorithm sql.NullString
		if err := rows.Scan(&ca.ID, &ca.Name, &ca.Type, &parentID, &commonName, &organization, &dnsNamesJSON,
			&keyAlgorithm, &signatureAlgorithm, &ca.Certificate, &ca.PrivateKeyEncrypted,
			&ca.NotBefore, &ca.NotAfter, &ca.CreatedAt); err != nil {
			return nil, err
		}
		if parentID.Valid {
			ca.ParentID = &parentID.String
		}
		ca.CommonName = commonName.String
		ca.Organization = organization.String
		ca.KeyAlgorithm = models.KeyAlgorithm(keyAlgorithm.String)
		ca.SignatureAlgorithm = models.SignatureAlgorithm(signatureAlgorithm.String)
		if dnsNamesJSON.Valid && dnsNamesJSON.String != "" {
			json.Unmarshal([]byte(dnsNamesJSON.String), &ca.DNSNames)
		}
		cas = append(cas, ca)
	}
	return cas, nil
}

// ClearAllData removes all data from the database (for import)
func (d *Database) ClearAllData() error {
	tables := []string{
		"notification_log",
		"notification_recipients",
		"certificates",
		"certificate_signing_requests",
		"certificate_authorities",
	}

	for _, table := range tables {
		if _, err := d.db.Exec("DELETE FROM " + table); err != nil {
			return err
		}
	}
	return nil
}

// ImportCA imports a CA with its encrypted private key
func (d *Database) ImportCA(ca *models.CertificateAuthority) error {
	dnsNamesJSON, _ := json.Marshal(ca.DNSNames)
	_, err := d.db.Exec(`
		INSERT INTO certificate_authorities (id, name, type, parent_id, common_name, organization, dns_names, key_algorithm, signature_algorithm, certificate, private_key_encrypted, not_before, not_after, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ca.ID, ca.Name, ca.Type, ca.ParentID, ca.CommonName, ca.Organization, string(dnsNamesJSON),
		ca.KeyAlgorithm, ca.SignatureAlgorithm, ca.Certificate, ca.PrivateKeyEncrypted,
		ca.NotBefore, ca.NotAfter, ca.CreatedAt)
	return err
}

// ImportCertificate imports a certificate
func (d *Database) ImportCertificate(cert *models.Certificate) error {
	dnsNamesJSON, _ := json.Marshal(cert.DNSNames)
	_, err := d.db.Exec(`
		INSERT INTO certificates (id, serial_number, ca_id, common_name, organization, dns_names, key_algorithm, signature_algorithm, type, certificate, not_before, not_after, revoked_at, revocation_reason, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cert.ID, cert.SerialNumber, cert.CAID, cert.CommonName, cert.Organization, string(dnsNamesJSON),
		cert.KeyAlgorithm, cert.SignatureAlgorithm, cert.Type, cert.Certificate,
		cert.NotBefore, cert.NotAfter, cert.RevokedAt, cert.RevocationReason, cert.CreatedAt)
	return err
}
