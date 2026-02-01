package api

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/dachony/easyca/internal/backup"
	"github.com/dachony/easyca/internal/ca"
	"github.com/dachony/easyca/internal/models"
	"github.com/dachony/easyca/internal/smtp"
	"github.com/dachony/easyca/internal/storage"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"software.sslmate.com/src/go-pkcs12"
)

type Handler struct {
	db          *storage.Database
	caService   *ca.CAService
	smtpService *smtp.SMTPService
}

func NewHandler(db *storage.Database, encryptionKey []byte) *Handler {
	return &Handler{
		db:          db,
		caService:   ca.NewCAService(encryptionKey),
		smtpService: smtp.NewSMTPService(encryptionKey),
	}
}

func (h *Handler) RegisterRoutes(r *gin.Engine) {
	api := r.Group("/api")
	{
		api.POST("/ca/root", h.CreateRootCA)
		api.POST("/ca/intermediate", h.CreateIntermediateCA)
		api.GET("/ca", h.ListCAs)
		api.GET("/ca/:id", h.GetCA)
		api.GET("/ca/:id/download", h.DownloadCA)
		api.GET("/ca/:id/chain", h.DownloadCAChain)

		api.POST("/certificates", h.CreateCertificate)
		api.POST("/certificates/import", h.ImportCertificate)
		api.GET("/certificates", h.ListCertificates)
		api.GET("/certificates/:id", h.GetCertificate)
		api.DELETE("/certificates/:id", h.DeleteCertificate)
		api.POST("/certificates/:id/revoke", h.RevokeCertificate)
		api.GET("/certificates/:id/download", h.DownloadCertificate)
		api.GET("/certificates/:id/chain", h.DownloadCertificateChain)
		api.POST("/certificates/:id/export/pkcs12", h.ExportPKCS12)
		api.GET("/certificates/:id/export/pkcs7", h.ExportPKCS7)

		// CSR endpoints
		api.POST("/csr/generate", h.GenerateCSR)
		api.POST("/csr/import", h.ImportCSR)
		api.GET("/csr", h.ListCSRs)
		api.GET("/csr/:id", h.GetCSR)
		api.GET("/csr/:id/download", h.DownloadCSR)
		api.POST("/csr/:id/sign", h.SignCSR)
		api.DELETE("/csr/:id", h.DeleteCSR)

		// Settings endpoints
		api.GET("/settings/smtp", h.GetSMTPConfig)
		api.POST("/settings/smtp", h.SaveSMTPConfig)
		api.POST("/settings/smtp/test", h.TestSMTP)
		api.GET("/settings/notifications", h.GetNotificationSettings)
		api.POST("/settings/notifications", h.SaveNotificationSettings)
		api.GET("/settings/defaults", h.GetDefaultSettings)
		api.POST("/settings/defaults", h.SaveDefaultSettings)
		api.GET("/settings/time", h.GetTimeSettings)
		api.POST("/settings/time", h.SaveTimeSettings)
		api.GET("/settings/time/current", h.GetCurrentTime)

		// Recipients endpoints
		api.GET("/recipients", h.ListRecipients)
		api.POST("/recipients", h.AddRecipient)
		api.DELETE("/recipients/:id", h.DeleteRecipient)

		// Notification log
		api.GET("/notifications/log", h.GetNotificationLogs)

		api.POST("/convert", h.ConvertCertificate)
		api.POST("/analyze", h.AnalyzeCertificate)

		api.GET("/audit", h.GetAuditLogs)

		// Backup endpoints
		api.POST("/backup/export", h.ExportBackup)
		api.POST("/backup/import", h.ImportBackup)
	}

	r.GET("/crl/:ca_id", h.GetCRL)
	r.GET("/health", h.HealthCheck)
}

func (h *Handler) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) CreateRootCA(c *gin.Context) {
	var req models.CreateRootCARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cert, privateKey, err := h.caService.GenerateRootCA(&req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	encryptedKey, err := h.caService.EncryptPrivateKey(privateKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt private key"})
		return
	}

	keyAlg := req.KeyAlgorithm
	if keyAlg == "" {
		keyAlg = models.KeyAlgorithmRSA4096
	}
	sigAlg := req.SignatureAlgorithm
	if sigAlg == "" {
		sigAlg = models.SignatureAlgorithmSHA256
	}

	caModel := &models.CertificateAuthority{
		ID:                  uuid.New().String(),
		Name:                req.Name,
		Type:                models.CATypeRoot,
		CommonName:          req.CommonName,
		Organization:        req.Organization,
		KeyAlgorithm:        keyAlg,
		SignatureAlgorithm:  sigAlg,
		Certificate:         cert.Raw,
		PrivateKeyEncrypted: encryptedKey,
		NotBefore:           cert.NotBefore,
		NotAfter:            cert.NotAfter,
		CreatedAt:           cert.NotBefore,
	}

	if err := h.db.CreateCA(caModel); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save CA"})
		return
	}

	h.db.AddAuditLog("create_root_ca", "ca", caModel.ID, "", fmt.Sprintf("Created Root CA: %s", req.Name))

	caModel.CertificatePEM = string(ca.CertToPEM(cert))
	c.JSON(http.StatusCreated, caModel)
}

func (h *Handler) CreateIntermediateCA(c *gin.Context) {
	var req models.CreateIntermediateCARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	parentCA, err := h.db.GetCA(req.ParentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "parent CA not found"})
		return
	}

	parentCert, err := parseRawCert(parentCA.Certificate)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse parent certificate"})
		return
	}

	parentKey, err := h.caService.DecryptPrivateKey(parentCA.PrivateKeyEncrypted)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decrypt parent key"})
		return
	}

	cert, privateKey, err := h.caService.GenerateIntermediateCA(&req, parentCert, parentKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	encryptedKey, err := h.caService.EncryptPrivateKey(privateKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt private key"})
		return
	}

	keyAlg := req.KeyAlgorithm
	if keyAlg == "" {
		keyAlg = models.KeyAlgorithmRSA4096
	}
	sigAlg := req.SignatureAlgorithm
	if sigAlg == "" {
		sigAlg = models.SignatureAlgorithmSHA256
	}

	caModel := &models.CertificateAuthority{
		ID:                  uuid.New().String(),
		Name:                req.Name,
		Type:                models.CATypeIntermediate,
		ParentID:            &req.ParentID,
		CommonName:          req.CommonName,
		Organization:        req.Organization,
		KeyAlgorithm:        keyAlg,
		SignatureAlgorithm:  sigAlg,
		Certificate:         cert.Raw,
		PrivateKeyEncrypted: encryptedKey,
		NotBefore:           cert.NotBefore,
		NotAfter:            cert.NotAfter,
		CreatedAt:           cert.NotBefore,
	}

	if err := h.db.CreateCA(caModel); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save CA"})
		return
	}

	h.db.AddAuditLog("create_intermediate_ca", "ca", caModel.ID, "", fmt.Sprintf("Created Intermediate CA: %s", req.Name))

	caModel.CertificatePEM = string(ca.CertToPEM(cert))
	c.JSON(http.StatusCreated, caModel)
}

func (h *Handler) ListCAs(c *gin.Context) {
	cas, err := h.db.ListCAs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	for i := range cas {
		cert, _ := parseRawCert(cas[i].Certificate)
		if cert != nil {
			cas[i].CertificatePEM = string(ca.CertToPEM(cert))
		}
	}

	c.JSON(http.StatusOK, cas)
}

func (h *Handler) GetCA(c *gin.Context) {
	id := c.Param("id")
	caModel, err := h.db.GetCA(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "CA not found"})
		return
	}

	cert, _ := parseRawCert(caModel.Certificate)
	if cert != nil {
		caModel.CertificatePEM = string(ca.CertToPEM(cert))
	}

	c.JSON(http.StatusOK, caModel)
}

func (h *Handler) CreateCertificate(c *gin.Context) {
	var req models.CreateCertificateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	caModel, err := h.db.GetCA(req.CAID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "CA not found"})
		return
	}

	caCert, err := parseRawCert(caModel.Certificate)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse CA certificate"})
		return
	}

	caKey, err := h.caService.DecryptPrivateKey(caModel.PrivateKeyEncrypted)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decrypt CA key"})
		return
	}

	cert, privateKey, err := h.caService.GenerateCertificate(&req, caCert, caKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	keyAlg := req.KeyAlgorithm
	if keyAlg == "" {
		keyAlg = models.KeyAlgorithmECDSAP256
	}
	sigAlg := req.SignatureAlgorithm
	if sigAlg == "" {
		sigAlg = models.SignatureAlgorithmSHA256
	}

	certModel := &models.Certificate{
		ID:                 uuid.New().String(),
		SerialNumber:       cert.SerialNumber.String(),
		CAID:               req.CAID,
		CommonName:         req.CommonName,
		Organization:       req.Organization,
		DNSNames:           req.DNSNames,
		KeyAlgorithm:       keyAlg,
		SignatureAlgorithm: sigAlg,
		Type:               req.Type,
		Certificate:        cert.Raw,
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		CreatedAt:          cert.NotBefore,
	}

	if err := h.db.CreateCertificate(certModel); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save certificate"})
		return
	}

	h.db.AddAuditLog("create_certificate", "certificate", certModel.ID, "",
		fmt.Sprintf("Created %s certificate: %s", req.Type, req.CommonName))

	response := gin.H{
		"certificate":     certModel,
		"certificate_pem": string(ca.CertToPEM(cert)),
		"private_key_pem": string(ca.KeyToPEM(privateKey)),
	}

	c.JSON(http.StatusCreated, response)
}

func (h *Handler) ListCertificates(c *gin.Context) {
	caID := c.Query("ca_id")

	var certs []models.Certificate
	var err error

	if caID != "" {
		certs, err = h.db.ListCertificatesByCA(caID)
	} else {
		certs, err = h.db.ListCertificates()
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	for i := range certs {
		cert, _ := parseRawCert(certs[i].Certificate)
		if cert != nil {
			certs[i].CertificatePEM = string(ca.CertToPEM(cert))
		}
	}

	c.JSON(http.StatusOK, certs)
}

func (h *Handler) GetCertificate(c *gin.Context) {
	id := c.Param("id")
	certModel, err := h.db.GetCertificate(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "certificate not found"})
		return
	}

	cert, _ := parseRawCert(certModel.Certificate)
	if cert != nil {
		certModel.CertificatePEM = string(ca.CertToPEM(cert))
	}

	c.JSON(http.StatusOK, certModel)
}

func (h *Handler) DeleteCertificate(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Reason       string `json:"reason"`
		Confirmation string `json:"confirmation"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if req.Reason == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "reason is required"})
		return
	}

	// Check if certificate exists
	cert, err := h.db.GetCertificate(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "certificate not found"})
		return
	}

	// Verify confirmation string (commonName-YYYYMMDD)
	expectedConfirmation := fmt.Sprintf("%s-%s", cert.CommonName, time.Now().Format("20060102"))
	if req.Confirmation != expectedConfirmation {
		c.JSON(http.StatusBadRequest, gin.H{"error": "confirmation does not match"})
		return
	}

	// Delete the certificate
	if err := h.db.DeleteCertificate(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete certificate"})
		return
	}

	h.db.AddAuditLog("delete_certificate", "certificate", id, "", fmt.Sprintf("Deleted certificate: %s, reason: %s", cert.CommonName, req.Reason))

	c.JSON(http.StatusOK, gin.H{"message": "certificate deleted"})
}

func (h *Handler) RevokeCertificate(c *gin.Context) {
	id := c.Param("id")

	var req models.RevokeCertificateRequest
	c.ShouldBindJSON(&req)

	reason := req.Reason
	if reason == "" {
		reason = "unspecified"
	}

	if err := h.db.RevokeCertificate(id, reason); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	h.db.AddAuditLog("revoke_certificate", "certificate", id, "", fmt.Sprintf("Revoked certificate, reason: %s", reason))

	c.JSON(http.StatusOK, gin.H{"message": "certificate revoked"})
}

func (h *Handler) DownloadCertificate(c *gin.Context) {
	id := c.Param("id")
	format := c.DefaultQuery("format", "pem")

	certModel, err := h.db.GetCertificate(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "certificate not found"})
		return
	}

	cert, err := parseRawCert(certModel.Certificate)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse certificate"})
		return
	}

	switch format {
	case "pem":
		c.Header("Content-Type", "application/x-pem-file")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.pem", certModel.CommonName))
		c.Data(http.StatusOK, "application/x-pem-file", ca.CertToPEM(cert))
	case "der":
		c.Header("Content-Type", "application/x-x509-ca-cert")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.der", certModel.CommonName))
		c.Data(http.StatusOK, "application/x-x509-ca-cert", cert.Raw)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid format, use 'pem' or 'der'"})
	}
}

func (h *Handler) GetCRL(c *gin.Context) {
	caID := c.Param("ca_id")

	caModel, err := h.db.GetCA(caID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "CA not found"})
		return
	}

	caCert, err := parseRawCert(caModel.Certificate)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse CA certificate"})
		return
	}

	caKey, err := h.caService.DecryptPrivateKey(caModel.PrivateKeyEncrypted)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decrypt CA key"})
		return
	}

	revokedCerts, err := h.db.GetRevokedCertificates(caID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	crlDER, err := h.caService.GenerateCRL(caCert, caKey, revokedCerts)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	crlPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	})

	c.Header("Content-Type", "application/pkix-crl")
	c.Data(http.StatusOK, "application/pkix-crl", crlPEM)
}

func (h *Handler) GetAuditLogs(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "100")
	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	logs, err := h.db.GetAuditLogs(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, logs)
}

func parseRawCert(raw []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(raw)
}

func (h *Handler) DownloadCA(c *gin.Context) {
	id := c.Param("id")
	format := c.DefaultQuery("format", "pem")

	caModel, err := h.db.GetCA(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "CA not found"})
		return
	}

	cert, err := parseRawCert(caModel.Certificate)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse certificate"})
		return
	}

	filename := caModel.Name

	switch format {
	case "pem":
		c.Header("Content-Type", "application/x-pem-file")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.pem", filename))
		c.Data(http.StatusOK, "application/x-pem-file", ca.CertToPEM(cert))
	case "der":
		c.Header("Content-Type", "application/x-x509-ca-cert")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.der", filename))
		c.Data(http.StatusOK, "application/x-x509-ca-cert", cert.Raw)
	case "crt":
		c.Header("Content-Type", "application/x-x509-ca-cert")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.crt", filename))
		c.Data(http.StatusOK, "application/x-x509-ca-cert", ca.CertToPEM(cert))
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid format"})
	}
}

func (h *Handler) DownloadCAChain(c *gin.Context) {
	id := c.Param("id")

	chain, err := h.buildCAChain(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var chainPEM []byte
	for _, cert := range chain {
		chainPEM = append(chainPEM, ca.CertToPEM(cert)...)
	}

	c.Header("Content-Type", "application/x-pem-file")
	c.Header("Content-Disposition", "attachment; filename=ca-chain.pem")
	c.Data(http.StatusOK, "application/x-pem-file", chainPEM)
}

func (h *Handler) buildCAChain(caID string) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate

	currentID := caID
	for currentID != "" {
		caModel, err := h.db.GetCA(currentID)
		if err != nil {
			return nil, fmt.Errorf("CA not found: %s", currentID)
		}

		cert, err := parseRawCert(caModel.Certificate)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate")
		}

		chain = append(chain, cert)

		if caModel.ParentID != nil {
			currentID = *caModel.ParentID
		} else {
			currentID = ""
		}
	}

	return chain, nil
}

func (h *Handler) DownloadCertificateChain(c *gin.Context) {
	id := c.Param("id")

	certModel, err := h.db.GetCertificate(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "certificate not found"})
		return
	}

	cert, err := parseRawCert(certModel.Certificate)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse certificate"})
		return
	}

	caChain, err := h.buildCAChain(certModel.CAID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var chainPEM []byte
	chainPEM = append(chainPEM, ca.CertToPEM(cert)...)
	for _, caCert := range caChain {
		chainPEM = append(chainPEM, ca.CertToPEM(caCert)...)
	}

	c.Header("Content-Type", "application/x-pem-file")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s-chain.pem", certModel.CommonName))
	c.Data(http.StatusOK, "application/x-pem-file", chainPEM)
}

func (h *Handler) ExportPKCS12(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Password      string `json:"password"`
		PrivateKeyPEM string `json:"private_key_pem"`
		IncludeChain  bool   `json:"include_chain"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.PrivateKeyPEM == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "private_key_pem is required"})
		return
	}

	certModel, err := h.db.GetCertificate(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "certificate not found"})
		return
	}

	cert, err := parseRawCert(certModel.Certificate)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse certificate"})
		return
	}

	block, _ := pem.Decode([]byte(req.PrivateKeyPEM))
	if block == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid private key PEM"})
		return
	}

	var privateKey interface{}
	// Try RSA PKCS1 first
	privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try EC private key
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS8 (generic)
			privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "failed to parse private key"})
				return
			}
		}
	}

	var caCerts []*x509.Certificate
	if req.IncludeChain {
		caCerts, _ = h.buildCAChain(certModel.CAID)
	}

	password := req.Password
	if password == "" {
		password = "changeit"
	}

	pfxData, err := pkcs12.Modern.Encode(privateKey, cert, caCerts, password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to create PKCS12: %v", err)})
		return
	}

	h.db.AddAuditLog("export_pkcs12", "certificate", id, "", fmt.Sprintf("Exported PKCS12: %s", certModel.CommonName))

	c.Header("Content-Type", "application/x-pkcs12")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.p12", certModel.CommonName))
	c.Data(http.StatusOK, "application/x-pkcs12", pfxData)
}

func (h *Handler) ExportPKCS7(c *gin.Context) {
	id := c.Param("id")
	includeChain := c.Query("include_chain") != "false"

	certModel, err := h.db.GetCertificate(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "certificate not found"})
		return
	}

	cert, err := parseRawCert(certModel.Certificate)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse certificate"})
		return
	}

	var certs []*x509.Certificate
	certs = append(certs, cert)

	if includeChain {
		chainCerts, _ := h.buildCAChain(certModel.CAID)
		certs = append(certs, chainCerts...)
	}

	p7bData, err := ca.CreatePKCS7(certs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to create PKCS7: %v", err)})
		return
	}

	h.db.AddAuditLog("export_pkcs7", "certificate", id, "", fmt.Sprintf("Exported PKCS7: %s", certModel.CommonName))

	c.Header("Content-Type", "application/x-pkcs7-certificates")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.p7b", certModel.CommonName))
	c.Data(http.StatusOK, "application/x-pkcs7-certificates", p7bData)
}

func (h *Handler) ImportCertificate(c *gin.Context) {
	var req struct {
		CAID           string `json:"ca_id" binding:"required"`
		CertificatePEM string `json:"certificate_pem" binding:"required"`
		CommonName     string `json:"common_name"`
		Type           string `json:"type"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	block, _ := pem.Decode([]byte(req.CertificatePEM))
	if block == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid certificate PEM"})
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to parse certificate"})
		return
	}

	_, err = h.db.GetCA(req.CAID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "CA not found"})
		return
	}

	commonName := req.CommonName
	if commonName == "" {
		commonName = cert.Subject.CommonName
	}

	certType := models.CertType(req.Type)
	if certType == "" {
		if len(cert.ExtKeyUsage) > 0 {
			for _, usage := range cert.ExtKeyUsage {
				if usage == x509.ExtKeyUsageServerAuth {
					certType = models.CertTypeServer
					break
				}
				if usage == x509.ExtKeyUsageClientAuth {
					certType = models.CertTypeClient
					break
				}
			}
		}
		if certType == "" {
			certType = models.CertTypeServer
		}
	}

	certModel := &models.Certificate{
		ID:           uuid.New().String(),
		SerialNumber: cert.SerialNumber.String(),
		CAID:         req.CAID,
		CommonName:   commonName,
		Type:         certType,
		Certificate:  cert.Raw,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		CreatedAt:    cert.NotBefore,
	}

	if err := h.db.CreateCertificate(certModel); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save certificate"})
		return
	}

	h.db.AddAuditLog("import_certificate", "certificate", certModel.ID, "",
		fmt.Sprintf("Imported certificate: %s", commonName))

	certModel.CertificatePEM = string(ca.CertToPEM(cert))
	c.JSON(http.StatusCreated, certModel)
}

func (h *Handler) ConvertCertificate(c *gin.Context) {
	var req struct {
		Input      string `json:"input" binding:"required"`
		FromFormat string `json:"from_format" binding:"required"`
		ToFormat   string `json:"to_format" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var certDER []byte

	switch req.FromFormat {
	case "pem":
		block, _ := pem.Decode([]byte(req.Input))
		if block == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid PEM data"})
			return
		}
		certDER = block.Bytes
	case "der":
		decoded, err := base64.StdEncoding.DecodeString(req.Input)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid base64-encoded DER data"})
			return
		}
		certDER = decoded
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid from_format, use 'pem' or 'der'"})
		return
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to parse certificate"})
		return
	}

	var output string
	var contentType string

	switch req.ToFormat {
	case "pem":
		output = string(ca.CertToPEM(cert))
		contentType = "application/x-pem-file"
	case "der":
		output = base64.StdEncoding.EncodeToString(cert.Raw)
		contentType = "application/x-x509-ca-cert"
	case "p7b", "pkcs7":
		p7bData, err := ca.CreatePKCS7([]*x509.Certificate{cert})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create PKCS7"})
			return
		}
		output = base64.StdEncoding.EncodeToString(p7bData)
		contentType = "application/x-pkcs7-certificates"
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid to_format, use 'pem', 'der', or 'p7b'"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"output":       output,
		"content_type": contentType,
		"subject":      cert.Subject.String(),
		"issuer":       cert.Issuer.String(),
		"not_before":   cert.NotBefore,
		"not_after":    cert.NotAfter,
	})
}

func (h *Handler) AnalyzeCertificate(c *gin.Context) {
	var req struct {
		Input string `json:"input" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	block, _ := pem.Decode([]byte(req.Input))
	if block == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid PEM data"})
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to parse certificate"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"subject":              cert.Subject.String(),
		"issuer":               cert.Issuer.String(),
		"serial_number":        cert.SerialNumber.String(),
		"not_before":           cert.NotBefore,
		"not_after":            cert.NotAfter,
		"signature_algorithm":  cert.SignatureAlgorithm.String(),
		"public_key_algorithm": cert.PublicKeyAlgorithm.String(),
		"is_ca":                cert.IsCA,
		"dns_names":            cert.DNSNames,
	})
}

// CSR Handlers

func (h *Handler) GenerateCSR(c *gin.Context) {
	var req models.GenerateCSRRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	csrPEM, privateKey, err := h.caService.GenerateCSR(&req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Parse CSR to extract subject info
	csr, err := ca.ParseCSRPEM(csrPEM)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse generated CSR"})
		return
	}

	csrModel := &models.CertificateSigningRequest{
		ID:                 uuid.New().String(),
		Name:               req.Name,
		CSRPEM:             string(csrPEM),
		CommonName:         csr.Subject.CommonName,
		Organization:       getFirst(csr.Subject.Organization),
		OrganizationalUnit: getFirst(csr.Subject.OrganizationalUnit),
		Country:            getFirst(csr.Subject.Country),
		State:              getFirst(csr.Subject.Province),
		Locality:           getFirst(csr.Subject.Locality),
		StreetAddress:      getFirst(csr.Subject.StreetAddress),
		PostalCode:         getFirst(csr.Subject.PostalCode),
		EmailAddress:       req.EmailAddress,
		DNSNames:           req.DNSNames,
		IPAddresses:        req.IPAddresses,
		Status:             models.CSRStatusPending,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}

	if err := h.db.CreateCSR(csrModel); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save CSR"})
		return
	}

	h.db.AddAuditLog("generate_csr", "csr", csrModel.ID, "", fmt.Sprintf("Generated CSR: %s", req.Name))

	c.JSON(http.StatusCreated, gin.H{
		"csr":             csrModel,
		"csr_pem":         string(csrPEM),
		"private_key_pem": string(ca.KeyToPEM(privateKey)),
	})
}

func (h *Handler) ImportCSR(c *gin.Context) {
	var req models.ImportCSRRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	csr, err := ca.ParseCSRPEM([]byte(req.CSRPEM))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid CSR PEM"})
		return
	}

	// Verify CSR signature
	if err := csr.CheckSignature(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "CSR signature verification failed"})
		return
	}

	var ipAddresses []string
	for _, ip := range csr.IPAddresses {
		ipAddresses = append(ipAddresses, ip.String())
	}

	csrModel := &models.CertificateSigningRequest{
		ID:                 uuid.New().String(),
		Name:               req.Name,
		CSRPEM:             req.CSRPEM,
		CommonName:         csr.Subject.CommonName,
		Organization:       getFirst(csr.Subject.Organization),
		OrganizationalUnit: getFirst(csr.Subject.OrganizationalUnit),
		Country:            getFirst(csr.Subject.Country),
		State:              getFirst(csr.Subject.Province),
		Locality:           getFirst(csr.Subject.Locality),
		StreetAddress:      getFirst(csr.Subject.StreetAddress),
		PostalCode:         getFirst(csr.Subject.PostalCode),
		EmailAddress:       getFirst(csr.EmailAddresses),
		DNSNames:           csr.DNSNames,
		IPAddresses:        ipAddresses,
		Status:             models.CSRStatusPending,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}

	if err := h.db.CreateCSR(csrModel); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save CSR"})
		return
	}

	h.db.AddAuditLog("import_csr", "csr", csrModel.ID, "", fmt.Sprintf("Imported CSR: %s", req.Name))

	c.JSON(http.StatusCreated, csrModel)
}

func (h *Handler) ListCSRs(c *gin.Context) {
	csrs, err := h.db.ListCSRs()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, csrs)
}

func (h *Handler) GetCSR(c *gin.Context) {
	id := c.Param("id")
	csr, err := h.db.GetCSR(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "CSR not found"})
		return
	}

	c.JSON(http.StatusOK, csr)
}

func (h *Handler) DownloadCSR(c *gin.Context) {
	id := c.Param("id")
	csrModel, err := h.db.GetCSR(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "CSR not found"})
		return
	}

	c.Header("Content-Type", "application/x-pem-file")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.csr", csrModel.Name))
	c.Data(http.StatusOK, "application/x-pem-file", []byte(csrModel.CSRPEM))
}

func (h *Handler) SignCSR(c *gin.Context) {
	id := c.Param("id")

	var req models.SignCSRRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	csrModel, err := h.db.GetCSR(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "CSR not found"})
		return
	}

	if csrModel.Status != models.CSRStatusPending {
		c.JSON(http.StatusBadRequest, gin.H{"error": "CSR is not pending"})
		return
	}

	csr, err := ca.ParseCSRPEM([]byte(csrModel.CSRPEM))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse CSR"})
		return
	}

	caModel, err := h.db.GetCA(req.CAID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "CA not found"})
		return
	}

	caCert, err := parseRawCert(caModel.Certificate)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse CA certificate"})
		return
	}

	caKey, err := h.caService.DecryptPrivateKey(caModel.PrivateKeyEncrypted)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decrypt CA key"})
		return
	}

	cert, err := h.caService.SignCSR(csr, &req, caCert, caKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	certModel := &models.Certificate{
		ID:           uuid.New().String(),
		SerialNumber: cert.SerialNumber.String(),
		CAID:         req.CAID,
		CommonName:   cert.Subject.CommonName,
		Type:         req.Type,
		Certificate:  cert.Raw,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		CreatedAt:    time.Now(),
	}

	if err := h.db.CreateCertificate(certModel); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save certificate"})
		return
	}

	// Update CSR status
	if err := h.db.UpdateCSRStatus(id, models.CSRStatusSigned, &certModel.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update CSR status"})
		return
	}

	h.db.AddAuditLog("sign_csr", "csr", id, "", fmt.Sprintf("Signed CSR %s, issued certificate %s", csrModel.Name, certModel.ID))

	certModel.CertificatePEM = string(ca.CertToPEM(cert))
	c.JSON(http.StatusOK, gin.H{
		"certificate":     certModel,
		"certificate_pem": string(ca.CertToPEM(cert)),
	})
}

func (h *Handler) DeleteCSR(c *gin.Context) {
	id := c.Param("id")

	csrModel, err := h.db.GetCSR(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "CSR not found"})
		return
	}

	if err := h.db.DeleteCSR(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete CSR"})
		return
	}

	h.db.AddAuditLog("delete_csr", "csr", id, "", fmt.Sprintf("Deleted CSR: %s", csrModel.Name))

	c.JSON(http.StatusOK, gin.H{"message": "CSR deleted"})
}

// SMTP Handlers

func (h *Handler) GetSMTPConfig(c *gin.Context) {
	config, err := h.db.GetSMTPConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if config == nil {
		c.JSON(http.StatusOK, nil)
		return
	}

	// Don't send password back
	config.PasswordEncrypted = nil
	c.JSON(http.StatusOK, config)
}

func (h *Handler) SaveSMTPConfig(c *gin.Context) {
	var req models.SaveSMTPConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Port == 0 {
		req.Port = 587
	}

	var encryptedPassword []byte
	if req.Password != "" {
		var err error
		encryptedPassword, err = h.smtpService.EncryptPassword(req.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt password"})
			return
		}
	} else {
		// Keep existing password if not provided
		existing, _ := h.db.GetSMTPConfig()
		if existing != nil {
			encryptedPassword = existing.PasswordEncrypted
		}
	}

	config := &models.SMTPConfig{
		Host:              req.Host,
		Port:              req.Port,
		Username:          req.Username,
		PasswordEncrypted: encryptedPassword,
		FromAddress:       req.FromAddress,
		TLSEnabled:        req.TLSEnabled,
		Enabled:           req.Enabled,
	}

	if err := h.db.SaveSMTPConfig(config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save SMTP config"})
		return
	}

	h.db.AddAuditLog("update_smtp_config", "settings", "", "", "Updated SMTP configuration")

	c.JSON(http.StatusOK, gin.H{"message": "SMTP configuration saved"})
}

func (h *Handler) TestSMTP(c *gin.Context) {
	var req models.TestSMTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	config, err := h.db.GetSMTPConfig()
	if err != nil || config == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "SMTP not configured"})
		return
	}

	if err := h.smtpService.SendTestEmail(config, req.ToEmail); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to send test email: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Test email sent successfully"})
}

// Notification Settings Handlers

func (h *Handler) GetNotificationSettings(c *gin.Context) {
	settings, err := h.db.GetNotificationSettings()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, settings)
}

func (h *Handler) SaveNotificationSettings(c *gin.Context) {
	var req models.SaveNotificationSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	settings := &models.NotificationSettings{
		ExpiryWarningDays:  req.ExpiryWarningDays,
		NotifyOnIssuance:   req.NotifyOnIssuance,
		NotifyOnRevocation: req.NotifyOnRevocation,
	}

	if err := h.db.SaveNotificationSettings(settings); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save settings"})
		return
	}

	h.db.AddAuditLog("update_notification_settings", "settings", "", "", "Updated notification settings")

	c.JSON(http.StatusOK, gin.H{"message": "Notification settings saved"})
}

// Default Settings Handlers

func (h *Handler) GetDefaultSettings(c *gin.Context) {
	settings, err := h.db.GetDefaultSettings()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, settings)
}

func (h *Handler) SaveDefaultSettings(c *gin.Context) {
	var req models.SaveDefaultSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	settings := &models.DefaultSettings{
		KeyAlgorithm:         models.KeyAlgorithm(req.KeyAlgorithm),
		SignatureAlgorithm:   models.SignatureAlgorithm(req.SignatureAlgorithm),
		ValidityDaysCA:       req.ValidityDaysCA,
		ValidityDaysCert:     req.ValidityDaysCert,
		Organization:         req.Organization,
		OrganizationalUnit:   req.OrganizationalUnit,
		Country:              req.Country,
		State:                req.State,
		Locality:             req.Locality,
	}

	if err := h.db.SaveDefaultSettings(settings); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save default settings"})
		return
	}

	h.db.AddAuditLog("update_default_settings", "settings", "", "", "Updated default settings")

	c.JSON(http.StatusOK, gin.H{"message": "Default settings saved"})
}

// Recipients Handlers

func (h *Handler) ListRecipients(c *gin.Context) {
	recipients, err := h.db.ListRecipients()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, recipients)
}

func (h *Handler) AddRecipient(c *gin.Context) {
	var req models.AddRecipientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	recipient := &models.NotificationRecipient{
		ID:            uuid.New().String(),
		Email:         req.Email,
		CertificateID: req.CertificateID,
		CAID:          req.CAID,
		IsGlobal:      req.IsGlobal,
		CreatedAt:     time.Now(),
	}

	if err := h.db.CreateRecipient(recipient); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add recipient"})
		return
	}

	h.db.AddAuditLog("add_recipient", "recipient", recipient.ID, "", fmt.Sprintf("Added notification recipient: %s", req.Email))

	c.JSON(http.StatusCreated, recipient)
}

func (h *Handler) DeleteRecipient(c *gin.Context) {
	id := c.Param("id")

	if err := h.db.DeleteRecipient(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete recipient"})
		return
	}

	h.db.AddAuditLog("delete_recipient", "recipient", id, "", "Deleted notification recipient")

	c.JSON(http.StatusOK, gin.H{"message": "Recipient deleted"})
}

// Notification Log Handler

func (h *Handler) GetNotificationLogs(c *gin.Context) {
	limitStr := c.DefaultQuery("limit", "100")
	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	logs, err := h.db.GetNotificationLogs(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, logs)
}

// Time Settings Handlers

func (h *Handler) GetTimeSettings(c *gin.Context) {
	settings, err := h.db.GetTimeSettings()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, settings)
}

func (h *Handler) SaveTimeSettings(c *gin.Context) {
	var req models.SaveTimeSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	settings := &models.TimeSettings{
		TimeSource: req.TimeSource,
		NTPServer:  req.NTPServer,
		Timezone:   req.Timezone,
		ManualTime: req.ManualTime,
	}

	if err := h.db.SaveTimeSettings(settings); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save time settings"})
		return
	}

	h.db.AddAuditLog("update_time_settings", "settings", "", "", fmt.Sprintf("Updated time settings: source=%s", req.TimeSource))

	c.JSON(http.StatusOK, gin.H{"message": "Time settings saved"})
}

func (h *Handler) GetCurrentTime(c *gin.Context) {
	settings, _ := h.db.GetTimeSettings()

	currentTime := time.Now()
	source := "host"

	if settings != nil {
		source = string(settings.TimeSource)
		if settings.Timezone != "" {
			loc, err := time.LoadLocation(settings.Timezone)
			if err == nil {
				currentTime = currentTime.In(loc)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"current_time": currentTime.Format(time.RFC3339),
		"timezone":     currentTime.Location().String(),
		"source":       source,
		"unix":         currentTime.Unix(),
	})
}

// Helper function
func getFirst(slice []string) string {
	if len(slice) > 0 {
		return slice[0]
	}
	return ""
}

// Backup Handlers

func (h *Handler) ExportBackup(c *gin.Context) {
	var req models.ExportBackupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password is required (minimum 8 characters)"})
		return
	}

	// Get all CAs with encrypted keys
	cas, err := h.db.GetAllCAsWithKeys()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get CAs"})
		return
	}

	// Convert CAs to backup format (decrypt private keys)
	var backupCAs []models.BackupCA
	for _, caModel := range cas {
		// Decrypt the private key
		privateKey, err := h.caService.DecryptPrivateKey(caModel.PrivateKeyEncrypted)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt CA private key"})
			return
		}

		// Parse certificate for PEM
		cert, _ := x509.ParseCertificate(caModel.Certificate)
		certPEM := ""
		if cert != nil {
			certPEM = string(ca.CertToPEM(cert))
		}

		backupCA := models.BackupCA{
			ID:                 caModel.ID,
			Name:               caModel.Name,
			Type:               caModel.Type,
			ParentID:           caModel.ParentID,
			CommonName:         caModel.CommonName,
			Organization:       caModel.Organization,
			KeyAlgorithm:       string(caModel.KeyAlgorithm),
			SignatureAlgorithm: string(caModel.SignatureAlgorithm),
			CertificatePEM:     certPEM,
			PrivateKeyPEM:      string(ca.KeyToPEM(privateKey)),
			NotBefore:          caModel.NotBefore.Format(time.RFC3339),
			NotAfter:           caModel.NotAfter.Format(time.RFC3339),
			CreatedAt:          caModel.CreatedAt.Format(time.RFC3339),
		}
		backupCAs = append(backupCAs, backupCA)
	}

	// Get all certificates
	certs, err := h.db.ListCertificates()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get certificates"})
		return
	}

	var backupCerts []models.BackupCertificate
	for _, cert := range certs {
		parsedCert, _ := x509.ParseCertificate(cert.Certificate)
		certPEM := ""
		if parsedCert != nil {
			certPEM = string(ca.CertToPEM(parsedCert))
		}

		var revokedAt, revocationReason *string
		if cert.RevokedAt != nil {
			t := cert.RevokedAt.Format(time.RFC3339)
			revokedAt = &t
		}
		if cert.RevocationReason != nil {
			revocationReason = cert.RevocationReason
		}

		backupCert := models.BackupCertificate{
			ID:                 cert.ID,
			SerialNumber:       cert.SerialNumber,
			CAID:               cert.CAID,
			CommonName:         cert.CommonName,
			Organization:       cert.Organization,
			DNSNames:           cert.DNSNames,
			KeyAlgorithm:       string(cert.KeyAlgorithm),
			SignatureAlgorithm: string(cert.SignatureAlgorithm),
			Type:               cert.Type,
			CertificatePEM:     certPEM,
			NotBefore:          cert.NotBefore.Format(time.RFC3339),
			NotAfter:           cert.NotAfter.Format(time.RFC3339),
			RevokedAt:          revokedAt,
			RevocationReason:   revocationReason,
			CreatedAt:          cert.CreatedAt.Format(time.RFC3339),
		}
		backupCerts = append(backupCerts, backupCert)
	}

	// Get CSRs
	csrs, _ := h.db.ListCSRs()

	// Get settings
	smtpConfig, _ := h.db.GetSMTPConfig()
	notificationSettings, _ := h.db.GetNotificationSettings()
	recipients, _ := h.db.ListRecipients()
	defaultSettings, _ := h.db.GetDefaultSettings()
	timeSettings, _ := h.db.GetTimeSettings()

	// Create backup data
	backupData := models.BackupData{
		Version:              "1.0",
		CreatedAt:            time.Now().Format(time.RFC3339),
		CAs:                  backupCAs,
		Certificates:         backupCerts,
		CSRs:                 csrs,
		SMTPConfig:           smtpConfig,
		NotificationSettings: notificationSettings,
		Recipients:           recipients,
		DefaultSettings:      defaultSettings,
		TimeSettings:         timeSettings,
	}

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(backupData, "", "  ")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create backup"})
		return
	}

	// Encrypt with password
	encrypted, err := backup.Encrypt(jsonData, req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt backup"})
		return
	}

	h.db.AddAuditLog("export_backup", "backup", "", "", "Exported backup")

	c.JSON(http.StatusOK, gin.H{
		"data":       encrypted,
		"created_at": backupData.CreatedAt,
		"stats": gin.H{
			"cas":          len(backupCAs),
			"certificates": len(backupCerts),
			"csrs":         len(csrs),
		},
	})
}

func (h *Handler) ImportBackup(c *gin.Context) {
	var req models.ImportBackupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password and data are required"})
		return
	}

	// Decrypt
	jsonData, err := backup.Decrypt(req.Data, req.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to decrypt backup - wrong password or corrupted data"})
		return
	}

	// Parse backup data
	var backupData models.BackupData
	if err := json.Unmarshal(jsonData, &backupData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid backup data format"})
		return
	}

	// Clear existing data
	if err := h.db.ClearAllData(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to clear existing data"})
		return
	}

	// Import CAs (in order - root first, then intermediate)
	for _, backupCA := range backupData.CAs {
		// Parse certificate PEM
		block, _ := pem.Decode([]byte(backupCA.CertificatePEM))
		if block == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid certificate PEM for CA %s", backupCA.Name)})
			return
		}
		certBytes := block.Bytes

		// Parse private key PEM and encrypt with current encryption key
		keyBlock, _ := pem.Decode([]byte(backupCA.PrivateKeyPEM))
		if keyBlock == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid private key PEM for CA %s", backupCA.Name)})
			return
		}

		// Parse private key
		var privateKey interface{}
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			privateKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
			if err != nil {
				privateKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Failed to parse private key for CA %s", backupCA.Name)})
					return
				}
			}
		}

		// Encrypt with current encryption key
		encryptedKey, err := h.caService.EncryptPrivateKey(privateKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt private key"})
			return
		}

		// Parse times
		notBefore, _ := time.Parse(time.RFC3339, backupCA.NotBefore)
		notAfter, _ := time.Parse(time.RFC3339, backupCA.NotAfter)
		createdAt, _ := time.Parse(time.RFC3339, backupCA.CreatedAt)

		caModel := &models.CertificateAuthority{
			ID:                  backupCA.ID,
			Name:                backupCA.Name,
			Type:                backupCA.Type,
			ParentID:            backupCA.ParentID,
			CommonName:          backupCA.CommonName,
			Organization:        backupCA.Organization,
			KeyAlgorithm:        models.KeyAlgorithm(backupCA.KeyAlgorithm),
			SignatureAlgorithm:  models.SignatureAlgorithm(backupCA.SignatureAlgorithm),
			Certificate:         certBytes,
			PrivateKeyEncrypted: encryptedKey,
			NotBefore:           notBefore,
			NotAfter:            notAfter,
			CreatedAt:           createdAt,
		}

		if err := h.db.ImportCA(caModel); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to import CA %s: %v", backupCA.Name, err)})
			return
		}
	}

	// Import certificates
	for _, backupCert := range backupData.Certificates {
		block, _ := pem.Decode([]byte(backupCert.CertificatePEM))
		if block == nil {
			continue
		}

		notBefore, _ := time.Parse(time.RFC3339, backupCert.NotBefore)
		notAfter, _ := time.Parse(time.RFC3339, backupCert.NotAfter)
		createdAt, _ := time.Parse(time.RFC3339, backupCert.CreatedAt)

		var revokedAt *time.Time
		if backupCert.RevokedAt != nil {
			t, _ := time.Parse(time.RFC3339, *backupCert.RevokedAt)
			revokedAt = &t
		}

		certModel := &models.Certificate{
			ID:                 backupCert.ID,
			SerialNumber:       backupCert.SerialNumber,
			CAID:               backupCert.CAID,
			CommonName:         backupCert.CommonName,
			Organization:       backupCert.Organization,
			DNSNames:           backupCert.DNSNames,
			KeyAlgorithm:       models.KeyAlgorithm(backupCert.KeyAlgorithm),
			SignatureAlgorithm: models.SignatureAlgorithm(backupCert.SignatureAlgorithm),
			Type:               backupCert.Type,
			Certificate:        block.Bytes,
			NotBefore:          notBefore,
			NotAfter:           notAfter,
			RevokedAt:          revokedAt,
			RevocationReason:   backupCert.RevocationReason,
			CreatedAt:          createdAt,
		}

		if err := h.db.ImportCertificate(certModel); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to import certificate %s", backupCert.CommonName)})
			return
		}
	}

	// Import CSRs
	for _, csr := range backupData.CSRs {
		h.db.CreateCSR(&csr)
	}

	// Import settings
	if backupData.SMTPConfig != nil {
		h.db.SaveSMTPConfig(backupData.SMTPConfig)
	}
	if backupData.NotificationSettings != nil {
		h.db.SaveNotificationSettings(backupData.NotificationSettings)
	}
	for _, recipient := range backupData.Recipients {
		h.db.CreateRecipient(&recipient)
	}
	if backupData.DefaultSettings != nil {
		h.db.SaveDefaultSettings(backupData.DefaultSettings)
	}
	if backupData.TimeSettings != nil {
		h.db.SaveTimeSettings(backupData.TimeSettings)
	}

	h.db.AddAuditLog("import_backup", "backup", "", "", fmt.Sprintf("Imported backup from %s", backupData.CreatedAt))

	c.JSON(http.StatusOK, gin.H{
		"message": "Backup imported successfully",
		"stats": gin.H{
			"cas":          len(backupData.CAs),
			"certificates": len(backupData.Certificates),
			"csrs":         len(backupData.CSRs),
		},
	})
}
