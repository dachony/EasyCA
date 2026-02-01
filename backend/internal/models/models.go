package models

import "time"

type CAType string

const (
	CATypeRoot         CAType = "root"
	CATypeIntermediate CAType = "intermediate"
)

type CertType string

const (
	CertTypeServer CertType = "server"
	CertTypeClient CertType = "client"
)

// KeyAlgorithm represents the key algorithm type
type KeyAlgorithm string

const (
	KeyAlgorithmRSA2048   KeyAlgorithm = "rsa2048"
	KeyAlgorithmRSA3072   KeyAlgorithm = "rsa3072"
	KeyAlgorithmRSA4096   KeyAlgorithm = "rsa4096"
	KeyAlgorithmECDSAP256 KeyAlgorithm = "ecdsa-p256"
	KeyAlgorithmECDSAP384 KeyAlgorithm = "ecdsa-p384"
	KeyAlgorithmECDSAP521 KeyAlgorithm = "ecdsa-p521"
)

// SignatureAlgorithm represents the signature/hash algorithm
type SignatureAlgorithm string

const (
	SignatureAlgorithmSHA256 SignatureAlgorithm = "sha256"
	SignatureAlgorithmSHA384 SignatureAlgorithm = "sha384"
	SignatureAlgorithmSHA512 SignatureAlgorithm = "sha512"
)

type CertificateAuthority struct {
	ID                  string             `json:"id"`
	Name                string             `json:"name"`
	Type                CAType             `json:"type"`
	ParentID            *string            `json:"parent_id,omitempty"`
	CommonName          string             `json:"common_name,omitempty"`
	Organization        string             `json:"organization,omitempty"`
	DNSNames            []string           `json:"dns_names,omitempty"`
	KeyAlgorithm        KeyAlgorithm       `json:"key_algorithm,omitempty"`
	SignatureAlgorithm  SignatureAlgorithm `json:"signature_algorithm,omitempty"`
	Certificate         []byte             `json:"-"`
	CertificatePEM      string             `json:"certificate_pem,omitempty"`
	PrivateKeyEncrypted []byte             `json:"-"`
	NotBefore           time.Time          `json:"not_before"`
	NotAfter            time.Time          `json:"not_after"`
	CreatedAt           time.Time          `json:"created_at"`
}

type Certificate struct {
	ID                 string             `json:"id"`
	SerialNumber       string             `json:"serial_number"`
	CAID               string             `json:"ca_id"`
	CommonName         string             `json:"common_name"`
	Organization       string             `json:"organization,omitempty"`
	DNSNames           []string           `json:"dns_names,omitempty"`
	KeyAlgorithm       KeyAlgorithm       `json:"key_algorithm,omitempty"`
	SignatureAlgorithm SignatureAlgorithm `json:"signature_algorithm,omitempty"`
	Type               CertType           `json:"type"`
	Certificate        []byte             `json:"-"`
	CertificatePEM     string             `json:"certificate_pem,omitempty"`
	NotBefore          time.Time          `json:"not_before"`
	NotAfter           time.Time          `json:"not_after"`
	RevokedAt          *time.Time         `json:"revoked_at,omitempty"`
	RevocationReason   *string            `json:"revocation_reason,omitempty"`
	CreatedAt          time.Time          `json:"created_at"`
}

type AuditLog struct {
	ID         int64     `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Action     string    `json:"action"`
	EntityType string    `json:"entity_type,omitempty"`
	EntityID   string    `json:"entity_id,omitempty"`
	UserID     string    `json:"user_id,omitempty"`
	Details    string    `json:"details,omitempty"`
}

// SubjectFields contains all X.509 subject fields
type SubjectFields struct {
	CommonName         string `json:"common_name" binding:"required"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizational_unit"`
	Country            string `json:"country"`
	State              string `json:"state"`
	Locality           string `json:"locality"`
	StreetAddress      string `json:"street_address"`
	PostalCode         string `json:"postal_code"`
	EmailAddress       string `json:"email_address"`
}

type CreateRootCARequest struct {
	Name               string             `json:"name" binding:"required"`
	ValidityDays       int                `json:"validity_days"`
	KeyAlgorithm       KeyAlgorithm       `json:"key_algorithm"`
	SignatureAlgorithm SignatureAlgorithm `json:"signature_algorithm"`
	SubjectFields
}

type CreateIntermediateCARequest struct {
	Name               string             `json:"name" binding:"required"`
	ParentID           string             `json:"parent_id" binding:"required"`
	ValidityDays       int                `json:"validity_days"`
	KeyAlgorithm       KeyAlgorithm       `json:"key_algorithm"`
	SignatureAlgorithm SignatureAlgorithm `json:"signature_algorithm"`
	SubjectFields
}

type CreateCertificateRequest struct {
	CAID               string             `json:"ca_id" binding:"required"`
	Type               CertType           `json:"type" binding:"required"`
	DNSNames           []string           `json:"dns_names"`
	IPAddresses        []string           `json:"ip_addresses"`
	ValidityDays       int                `json:"validity_days"`
	KeyAlgorithm       KeyAlgorithm       `json:"key_algorithm"`
	SignatureAlgorithm SignatureAlgorithm `json:"signature_algorithm"`
	SubjectFields
}

type RevokeCertificateRequest struct {
	Reason string `json:"reason"`
}

// CSR Models
type CSRStatus string

const (
	CSRStatusPending  CSRStatus = "pending"
	CSRStatusSigned   CSRStatus = "signed"
	CSRStatusRejected CSRStatus = "rejected"
)

type CertificateSigningRequest struct {
	ID                    string     `json:"id"`
	Name                  string     `json:"name"`
	CSRPEM                string     `json:"csr_pem"`
	CommonName            string     `json:"common_name"`
	Organization          string     `json:"organization"`
	OrganizationalUnit    string     `json:"organizational_unit"`
	Country               string     `json:"country"`
	State                 string     `json:"state"`
	Locality              string     `json:"locality"`
	StreetAddress         string     `json:"street_address"`
	PostalCode            string     `json:"postal_code"`
	EmailAddress          string     `json:"email_address"`
	DNSNames              []string   `json:"dns_names"`
	IPAddresses           []string   `json:"ip_addresses"`
	Status                CSRStatus  `json:"status"`
	SignedCertificateID   *string    `json:"signed_certificate_id,omitempty"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

type GenerateCSRRequest struct {
	Name         string       `json:"name" binding:"required"`
	DNSNames     []string     `json:"dns_names"`
	IPAddresses  []string     `json:"ip_addresses"`
	KeyAlgorithm KeyAlgorithm `json:"key_algorithm"`
	SubjectFields
}

type ImportCSRRequest struct {
	Name   string `json:"name" binding:"required"`
	CSRPEM string `json:"csr_pem" binding:"required"`
}

type SignCSRRequest struct {
	CAID         string   `json:"ca_id" binding:"required"`
	Type         CertType `json:"type" binding:"required"`
	ValidityDays int      `json:"validity_days"`
}

// SMTP Models
type SMTPConfig struct {
	ID                int       `json:"id"`
	Host              string    `json:"host"`
	Port              int       `json:"port"`
	Username          string    `json:"username"`
	PasswordEncrypted []byte    `json:"-"`
	Password          string    `json:"password,omitempty"`
	FromAddress       string    `json:"from_address"`
	TLSEnabled        bool      `json:"tls_enabled"`
	Enabled           bool      `json:"enabled"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type NotificationRecipient struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	CertificateID *string   `json:"certificate_id,omitempty"`
	CAID          *string   `json:"ca_id,omitempty"`
	IsGlobal      bool      `json:"is_global"`
	CreatedAt     time.Time `json:"created_at"`
}

type NotificationSettings struct {
	ID                  int    `json:"id"`
	ExpiryWarningDays   string `json:"expiry_warning_days"`
	NotifyOnIssuance    bool   `json:"notify_on_issuance"`
	NotifyOnRevocation  bool   `json:"notify_on_revocation"`
}

type NotificationLog struct {
	ID              int64     `json:"id"`
	CertificateID   *string   `json:"certificate_id,omitempty"`
	CAID            *string   `json:"ca_id,omitempty"`
	NotificationType string   `json:"notification_type"`
	RecipientEmail  string    `json:"recipient_email"`
	DaysUntilExpiry *int      `json:"days_until_expiry,omitempty"`
	SentAt          time.Time `json:"sent_at"`
	Status          string    `json:"status"`
	ErrorMessage    *string   `json:"error_message,omitempty"`
}

type SaveSMTPConfigRequest struct {
	Host        string `json:"host" binding:"required"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	FromAddress string `json:"from_address" binding:"required"`
	TLSEnabled  bool   `json:"tls_enabled"`
	Enabled     bool   `json:"enabled"`
}

type TestSMTPRequest struct {
	ToEmail string `json:"to_email" binding:"required,email"`
}

type SaveNotificationSettingsRequest struct {
	ExpiryWarningDays  string `json:"expiry_warning_days"`
	NotifyOnIssuance   bool   `json:"notify_on_issuance"`
	NotifyOnRevocation bool   `json:"notify_on_revocation"`
}

type AddRecipientRequest struct {
	Email         string  `json:"email" binding:"required,email"`
	CertificateID *string `json:"certificate_id,omitempty"`
	CAID          *string `json:"ca_id,omitempty"`
	IsGlobal      bool    `json:"is_global"`
}

// Default Settings
type DefaultSettings struct {
	ID                   int                `json:"id"`
	KeyAlgorithm         KeyAlgorithm       `json:"key_algorithm"`
	SignatureAlgorithm   SignatureAlgorithm `json:"signature_algorithm"`
	ValidityDaysCA       int                `json:"validity_days_ca"`
	ValidityDaysCert     int                `json:"validity_days_cert"`
	Organization         string             `json:"organization"`
	OrganizationalUnit   string             `json:"organizational_unit"`
	Country              string             `json:"country"`
	State                string             `json:"state"`
	Locality             string             `json:"locality"`
}

type SaveDefaultSettingsRequest struct {
	KeyAlgorithm         string `json:"key_algorithm"`
	SignatureAlgorithm   string `json:"signature_algorithm"`
	ValidityDaysCA       int    `json:"validity_days_ca"`
	ValidityDaysCert     int    `json:"validity_days_cert"`
	Organization         string `json:"organization"`
	OrganizationalUnit   string `json:"organizational_unit"`
	Country              string `json:"country"`
	State                string `json:"state"`
	Locality             string `json:"locality"`
}

// Time Settings
type TimeSource string

const (
	TimeSourceHost   TimeSource = "host"
	TimeSourceNTP    TimeSource = "ntp"
	TimeSourceManual TimeSource = "manual"
)

type TimeSettings struct {
	ID           int        `json:"id"`
	TimeSource   TimeSource `json:"time_source"`
	NTPServer    string     `json:"ntp_server"`
	Timezone     string     `json:"timezone"`
	ManualTime   string     `json:"manual_time,omitempty"`
	LastSyncedAt string     `json:"last_synced_at,omitempty"`
}

type SaveTimeSettingsRequest struct {
	TimeSource TimeSource `json:"time_source"`
	NTPServer  string     `json:"ntp_server"`
	Timezone   string     `json:"timezone"`
	ManualTime string     `json:"manual_time,omitempty"`
}

// Backup Models
type BackupData struct {
	Version              string                        `json:"version"`
	CreatedAt            string                        `json:"created_at"`
	CAs                  []BackupCA                    `json:"cas"`
	Certificates         []BackupCertificate           `json:"certificates"`
	CSRs                 []CertificateSigningRequest   `json:"csrs"`
	SMTPConfig           *SMTPConfig                   `json:"smtp_config,omitempty"`
	NotificationSettings *NotificationSettings         `json:"notification_settings,omitempty"`
	Recipients           []NotificationRecipient       `json:"recipients"`
	DefaultSettings      *DefaultSettings              `json:"default_settings,omitempty"`
	TimeSettings         *TimeSettings                 `json:"time_settings,omitempty"`
}

type BackupCA struct {
	ID                  string     `json:"id"`
	Name                string     `json:"name"`
	Type                CAType     `json:"type"`
	ParentID            *string    `json:"parent_id,omitempty"`
	CommonName          string     `json:"common_name"`
	Organization        string     `json:"organization"`
	KeyAlgorithm        string     `json:"key_algorithm"`
	SignatureAlgorithm  string     `json:"signature_algorithm"`
	CertificatePEM      string     `json:"certificate_pem"`
	PrivateKeyPEM       string     `json:"private_key_pem"`
	NotBefore           string     `json:"not_before"`
	NotAfter            string     `json:"not_after"`
	CreatedAt           string     `json:"created_at"`
}

type BackupCertificate struct {
	ID                 string   `json:"id"`
	SerialNumber       string   `json:"serial_number"`
	CAID               string   `json:"ca_id"`
	CommonName         string   `json:"common_name"`
	Organization       string   `json:"organization"`
	DNSNames           []string `json:"dns_names"`
	KeyAlgorithm       string   `json:"key_algorithm"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	Type               CertType `json:"type"`
	CertificatePEM     string   `json:"certificate_pem"`
	NotBefore          string   `json:"not_before"`
	NotAfter           string   `json:"not_after"`
	RevokedAt          *string  `json:"revoked_at,omitempty"`
	RevocationReason   *string  `json:"revocation_reason,omitempty"`
	CreatedAt          string   `json:"created_at"`
}

type ExportBackupRequest struct {
	Password string `json:"password" binding:"required,min=8"`
}

type ImportBackupRequest struct {
	Password string `json:"password" binding:"required"`
	Data     string `json:"data" binding:"required"`
}
