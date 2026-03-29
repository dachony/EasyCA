package acme

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dachony/easyca/internal/ca"
	"github.com/dachony/easyca/internal/models"
	"github.com/dachony/easyca/internal/storage"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type ACMEHandler struct {
	db        *storage.Database
	caService *ca.CAService
	baseURL   string
}

func NewACMEHandler(db *storage.Database, caService *ca.CAService, baseURL string) *ACMEHandler {
	return &ACMEHandler{db: db, caService: caService, baseURL: baseURL}
}

func (h *ACMEHandler) RegisterRoutes(r *gin.Engine) {
	acme := r.Group("/acme")
	{
		acme.GET("/directory", h.Directory)
		acme.HEAD("/new-nonce", h.NewNonce)
		acme.GET("/new-nonce", h.NewNonce)
		acme.POST("/new-account", h.NewAccount)
		acme.POST("/new-order", h.NewOrder)
		acme.POST("/order/:id", h.GetOrder)
		acme.POST("/order/:id/finalize", h.FinalizeOrder)
		acme.POST("/authz/:id", h.GetAuthorization)
		acme.POST("/challenge/:id", h.RespondToChallenge)
		acme.POST("/certificate/:id", h.GetCertificate)

		// HTTP-01 challenge validation endpoint
		r.GET("/.well-known/acme-challenge/:token", h.ServeChallenge)
	}
}

// Directory returns ACME directory resource
func (h *ACMEHandler) Directory(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"newNonce":   h.baseURL + "/acme/new-nonce",
		"newAccount": h.baseURL + "/acme/new-account",
		"newOrder":   h.baseURL + "/acme/new-order",
		"meta": gin.H{
			"termsOfService": h.baseURL + "/terms",
			"website":        h.baseURL,
			"caaIdentities":  []string{"easyca.local"},
		},
	})
}

// NewNonce generates a fresh nonce
func (h *ACMEHandler) NewNonce(c *gin.Context) {
	nonce := generateNonce()
	h.db.CreateACMENonce(nonce)
	c.Header("Replay-Nonce", nonce)
	c.Header("Cache-Control", "no-store")
	if c.Request.Method == "HEAD" {
		c.Status(http.StatusOK)
	} else {
		c.Status(http.StatusNoContent)
	}
}

func (h *ACMEHandler) addNonce(c *gin.Context) {
	nonce := generateNonce()
	h.db.CreateACMENonce(nonce)
	c.Header("Replay-Nonce", nonce)
}

// NewAccount creates or retrieves an ACME account
func (h *ACMEHandler) NewAccount(c *gin.Context) {
	h.addNonce(c)

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		acmeError(c, "malformed", "Failed to read request body")
		return
	}

	// Parse JWS (simplified - extract payload)
	var jws struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(body, &jws); err != nil {
		acmeError(c, "malformed", "Invalid JWS")
		return
	}

	// Decode protected header to get JWK
	protectedBytes, _ := base64URLDecode(jws.Protected)
	var protectedHeader struct {
		Alg  string          `json:"alg"`
		JWK  json.RawMessage `json:"jwk"`
		Nonce string         `json:"nonce"`
		URL  string          `json:"url"`
	}
	json.Unmarshal(protectedBytes, &protectedHeader)

	// Use JWK as account key identifier
	keyThumbprint := base64.RawURLEncoding.EncodeToString(protectedBytes[:32])

	// Decode payload
	payloadBytes, _ := base64URLDecode(jws.Payload)
	var payload struct {
		TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
		Contact              []string `json:"contact"`
		OnlyReturnExisting   bool     `json:"onlyReturnExisting"`
	}
	json.Unmarshal(payloadBytes, &payload)

	// Check existing account
	existing, err := h.db.GetACMEAccountByKey(keyThumbprint)
	if err == nil {
		c.Header("Location", fmt.Sprintf("%s/acme/account/%s", h.baseURL, existing.ID))
		c.JSON(http.StatusOK, gin.H{
			"status":  existing.Status,
			"contact": strings.Split(existing.Contact[0], ","),
			"orders":  fmt.Sprintf("%s/acme/account/%s/orders", h.baseURL, existing.ID),
		})
		return
	}

	if payload.OnlyReturnExisting {
		acmeError(c, "accountDoesNotExist", "Account not found")
		return
	}

	// Create new account
	account := &models.ACMEAccount{
		ID:        uuid.New().String(),
		Key:       keyThumbprint,
		Contact:   payload.Contact,
		Status:    models.ACMEAccountValid,
		CreatedAt: time.Now(),
	}

	contactStr := strings.Join(payload.Contact, ",")
	if err := h.db.CreateACMEAccount(account.ID, keyThumbprint, contactStr); err != nil {
		acmeError(c, "serverInternal", "Failed to create account")
		return
	}

	c.Header("Location", fmt.Sprintf("%s/acme/account/%s", h.baseURL, account.ID))
	c.JSON(http.StatusCreated, gin.H{
		"status":  "valid",
		"contact": payload.Contact,
		"orders":  fmt.Sprintf("%s/acme/account/%s/orders", h.baseURL, account.ID),
	})
}

// NewOrder creates a new certificate order
func (h *ACMEHandler) NewOrder(c *gin.Context) {
	h.addNonce(c)

	body, _ := io.ReadAll(c.Request.Body)
	var jws struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	json.Unmarshal(body, &jws)

	payloadBytes, _ := base64URLDecode(jws.Payload)
	var payload struct {
		Identifiers []models.ACMEIdentifier `json:"identifiers"`
		NotBefore   string                  `json:"notBefore,omitempty"`
		NotAfter    string                  `json:"notAfter,omitempty"`
	}
	json.Unmarshal(payloadBytes, &payload)

	if len(payload.Identifiers) == 0 {
		acmeError(c, "malformed", "No identifiers specified")
		return
	}

	// Get default CA for ACME (first available)
	cas, err := h.db.ListCAs()
	if err != nil || len(cas) == 0 {
		acmeError(c, "serverInternal", "No CA available for ACME")
		return
	}
	caID := cas[0].ID

	orderID := uuid.New().String()
	expires := time.Now().Add(7 * 24 * time.Hour)

	identJSON, _ := json.Marshal(payload.Identifiers)

	if err := h.db.CreateACMEOrder(orderID, "", string(models.ACMEOrderPending), string(identJSON), expires, caID); err != nil {
		acmeError(c, "serverInternal", "Failed to create order")
		return
	}

	// Create authorizations for each identifier
	var authzURLs []string
	for _, ident := range payload.Identifiers {
		authzID := uuid.New().String()
		token := generateToken()

		h.db.CreateACMEAuthorization(authzID, orderID, ident.Type, ident.Value, expires, token)

		// Create HTTP-01 challenge
		challID := uuid.New().String()
		h.db.CreateACMEChallenge(challID, authzID, "http-01", token)

		authzURLs = append(authzURLs, fmt.Sprintf("%s/acme/authz/%s", h.baseURL, authzID))
	}

	c.Header("Location", fmt.Sprintf("%s/acme/order/%s", h.baseURL, orderID))
	c.JSON(http.StatusCreated, gin.H{
		"status":         "pending",
		"expires":        expires.Format(time.RFC3339),
		"identifiers":    payload.Identifiers,
		"authorizations": authzURLs,
		"finalize":       fmt.Sprintf("%s/acme/order/%s/finalize", h.baseURL, orderID),
	})
}

// GetOrder returns order status
func (h *ACMEHandler) GetOrder(c *gin.Context) {
	h.addNonce(c)
	id := c.Param("id")

	order, err := h.db.GetACMEOrder(id)
	if err != nil {
		acmeError(c, "malformed", "Order not found")
		return
	}

	var identifiers []models.ACMEIdentifier
	json.Unmarshal([]byte(order.Identifiers), &identifiers)

	// Get authorization URLs
	authzs, _ := h.db.GetACMEAuthorizationsByOrder(id)
	var authzURLs []string
	for _, a := range authzs {
		authzURLs = append(authzURLs, fmt.Sprintf("%s/acme/authz/%s", h.baseURL, a.ID))
	}

	resp := gin.H{
		"status":         order.Status,
		"expires":        order.Expires.Format(time.RFC3339),
		"identifiers":    identifiers,
		"authorizations": authzURLs,
		"finalize":       fmt.Sprintf("%s/acme/order/%s/finalize", h.baseURL, id),
	}

	if order.CertificateID != nil {
		resp["certificate"] = fmt.Sprintf("%s/acme/certificate/%s", h.baseURL, *order.CertificateID)
	}

	c.JSON(http.StatusOK, resp)
}

// GetAuthorization returns authorization with challenges
func (h *ACMEHandler) GetAuthorization(c *gin.Context) {
	h.addNonce(c)
	id := c.Param("id")

	authz, err := h.db.GetACMEAuthorization(id)
	if err != nil {
		acmeError(c, "malformed", "Authorization not found")
		return
	}

	challenges, _ := h.db.GetACMEChallengesByAuthz(id)
	var challResp []gin.H
	for _, ch := range challenges {
		entry := gin.H{
			"type":   ch.Type,
			"url":    fmt.Sprintf("%s/acme/challenge/%s", h.baseURL, ch.ID),
			"token":  ch.Token,
			"status": ch.Status,
		}
		if ch.Validated != nil {
			entry["validated"] = ch.Validated.Format(time.RFC3339)
		}
		challResp = append(challResp, entry)
	}

	c.JSON(http.StatusOK, gin.H{
		"identifier": gin.H{
			"type":  authz.IdentifierType,
			"value": authz.IdentifierValue,
		},
		"status":     authz.Status,
		"expires":    authz.Expires.Format(time.RFC3339),
		"challenges": challResp,
	})
}

// RespondToChallenge triggers challenge validation
func (h *ACMEHandler) RespondToChallenge(c *gin.Context) {
	h.addNonce(c)
	id := c.Param("id")

	challenge, err := h.db.GetACMEChallenge(id)
	if err != nil {
		acmeError(c, "malformed", "Challenge not found")
		return
	}

	// Mark challenge as valid (simplified - in production, would do HTTP-01 validation)
	now := time.Now()
	h.db.UpdateACMEChallengeStatus(id, string(models.ACMEChallengeValid), &now)

	// Update authorization status
	h.db.UpdateACMEAuthorizationStatus(challenge.AuthorizationID, string(models.ACMEAuthzValid))

	// Check if all authorizations for the order are valid
	authz, _ := h.db.GetACMEAuthorization(challenge.AuthorizationID)
	if authz != nil {
		authzs, _ := h.db.GetACMEAuthorizationsByOrder(authz.OrderID)
		allValid := true
		for _, a := range authzs {
			if a.Status != string(models.ACMEAuthzValid) {
				allValid = false
				break
			}
		}
		if allValid {
			h.db.UpdateACMEOrderStatus(authz.OrderID, string(models.ACMEOrderReady))
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"type":      challenge.Type,
		"url":       fmt.Sprintf("%s/acme/challenge/%s", h.baseURL, id),
		"token":     challenge.Token,
		"status":    "valid",
		"validated": now.Format(time.RFC3339),
	})
}

// FinalizeOrder processes CSR and issues certificate
func (h *ACMEHandler) FinalizeOrder(c *gin.Context) {
	h.addNonce(c)
	id := c.Param("id")

	order, err := h.db.GetACMEOrder(id)
	if err != nil {
		acmeError(c, "malformed", "Order not found")
		return
	}

	if order.Status != string(models.ACMEOrderReady) {
		acmeError(c, "orderNotReady", "Order is not ready for finalization")
		return
	}

	body, _ := io.ReadAll(c.Request.Body)
	var jws struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	json.Unmarshal(body, &jws)

	payloadBytes, _ := base64URLDecode(jws.Payload)
	var payload struct {
		CSR string `json:"csr"`
	}
	json.Unmarshal(payloadBytes, &payload)

	// Decode CSR
	csrDER, err := base64.RawURLEncoding.DecodeString(payload.CSR)
	if err != nil {
		acmeError(c, "badCSR", "Invalid CSR encoding")
		return
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		acmeError(c, "badCSR", "Invalid CSR")
		return
	}

	// Get CA
	caModel, err := h.db.GetCA(order.CAID)
	if err != nil {
		acmeError(c, "serverInternal", "CA not found")
		return
	}

	caCert, err := x509.ParseCertificate(caModel.Certificate)
	if err != nil {
		acmeError(c, "serverInternal", "Failed to parse CA")
		return
	}

	caKey, err := h.caService.DecryptPrivateKey(caModel.PrivateKeyEncrypted)
	if err != nil {
		acmeError(c, "serverInternal", "Failed to decrypt CA key")
		return
	}

	// Sign CSR
	signReq := &models.SignCSRRequest{
		CAID:         order.CAID,
		Type:         models.CertTypeServer,
		ValidityDays: 90, // ACME standard
	}
	cert, err := h.caService.SignCSR(csr, signReq, caCert, caKey)
	if err != nil {
		acmeError(c, "serverInternal", "Failed to issue certificate")
		return
	}

	// Save certificate
	certModel := &models.Certificate{
		ID:           uuid.New().String(),
		SerialNumber: cert.SerialNumber.String(),
		CAID:         order.CAID,
		CommonName:   cert.Subject.CommonName,
		Type:         models.CertTypeServer,
		Certificate:  cert.Raw,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		CreatedAt:    time.Now(),
	}
	h.db.CreateCertificate(certModel)

	// Update order
	h.db.UpdateACMEOrderStatus(id, string(models.ACMEOrderValid))
	h.db.UpdateACMEOrderCertificate(id, certModel.ID)

	h.db.AddAuditLog("acme_issue", "certificate", certModel.ID, "acme",
		fmt.Sprintf("ACME issued certificate: %s", cert.Subject.CommonName))

	var identifiers []models.ACMEIdentifier
	json.Unmarshal([]byte(order.Identifiers), &identifiers)

	c.Header("Location", fmt.Sprintf("%s/acme/order/%s", h.baseURL, id))
	c.JSON(http.StatusOK, gin.H{
		"status":      "valid",
		"identifiers": identifiers,
		"finalize":    fmt.Sprintf("%s/acme/order/%s/finalize", h.baseURL, id),
		"certificate": fmt.Sprintf("%s/acme/certificate/%s", h.baseURL, certModel.ID),
	})
}

// GetCertificate returns the issued certificate in PEM format
func (h *ACMEHandler) GetCertificate(c *gin.Context) {
	h.addNonce(c)
	id := c.Param("id")

	certModel, err := h.db.GetCertificate(id)
	if err != nil {
		acmeError(c, "malformed", "Certificate not found")
		return
	}

	cert, err := x509.ParseCertificate(certModel.Certificate)
	if err != nil {
		acmeError(c, "serverInternal", "Failed to parse certificate")
		return
	}

	certPEM := ca.CertToPEM(cert)

	// Also include CA chain
	caModel, _ := h.db.GetCA(certModel.CAID)
	if caModel != nil {
		caCert, _ := x509.ParseCertificate(caModel.Certificate)
		if caCert != nil {
			certPEM = append(certPEM, ca.CertToPEM(caCert)...)
		}
	}

	c.Data(http.StatusOK, "application/pem-certificate-chain", certPEM)
}

// ServeChallenge serves HTTP-01 challenge responses
func (h *ACMEHandler) ServeChallenge(c *gin.Context) {
	token := c.Param("token")

	challenge, err := h.db.GetACMEChallengeByToken(token)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}

	// In a real implementation, this would return token.thumbprint
	// For simplicity, return just the token
	c.String(http.StatusOK, challenge.Token)
}

// Helper functions

func acmeError(c *gin.Context, errType, detail string) {
	c.JSON(http.StatusBadRequest, gin.H{
		"type":   "urn:ietf:params:acme:error:" + errType,
		"detail": detail,
		"status": http.StatusBadRequest,
	})
}

func generateNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func base64URLDecode(s string) ([]byte, error) {
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}
