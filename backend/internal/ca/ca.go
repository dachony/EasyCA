package ca

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"

	"github.com/dachony/easyca/internal/models"
)

type CAService struct {
	encryptionKey []byte
}

func NewCAService(encryptionKey []byte) *CAService {
	key := sha256.Sum256(encryptionKey)
	return &CAService{encryptionKey: key[:]}
}

// generatePrivateKey generates a private key based on the algorithm
func generatePrivateKey(algorithm models.KeyAlgorithm) (crypto.PrivateKey, error) {
	switch algorithm {
	case models.KeyAlgorithmRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case models.KeyAlgorithmRSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case models.KeyAlgorithmRSA4096, "":
		return rsa.GenerateKey(rand.Reader, 4096)
	case models.KeyAlgorithmECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case models.KeyAlgorithmECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case models.KeyAlgorithmECDSAP521:
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return rsa.GenerateKey(rand.Reader, 4096)
	}
}

// getSignatureAlgorithm returns the x509 signature algorithm based on key type and hash
func getSignatureAlgorithm(key crypto.PrivateKey, sigAlg models.SignatureAlgorithm) x509.SignatureAlgorithm {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		switch sigAlg {
		case models.SignatureAlgorithmSHA384:
			return x509.SHA384WithRSA
		case models.SignatureAlgorithmSHA512:
			return x509.SHA512WithRSA
		default:
			return x509.SHA256WithRSA
		}
	case *ecdsa.PrivateKey:
		// For ECDSA, signature algorithm depends on curve size
		switch k.Curve {
		case elliptic.P384():
			if sigAlg == models.SignatureAlgorithmSHA512 {
				return x509.ECDSAWithSHA512
			}
			return x509.ECDSAWithSHA384
		case elliptic.P521():
			return x509.ECDSAWithSHA512
		default:
			if sigAlg == models.SignatureAlgorithmSHA384 {
				return x509.ECDSAWithSHA384
			}
			return x509.ECDSAWithSHA256
		}
	default:
		return x509.SHA256WithRSA
	}
}

// getPublicKey extracts the public key from a private key
func getPublicKey(key crypto.PrivateKey) crypto.PublicKey {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func (s *CAService) GenerateRootCA(req *models.CreateRootCARequest) (*x509.Certificate, crypto.PrivateKey, error) {
	keyAlgorithm := req.KeyAlgorithm
	if keyAlgorithm == "" {
		keyAlgorithm = models.KeyAlgorithmRSA4096 // Default for Root CA
	}

	privateKey, err := generatePrivateKey(keyAlgorithm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	validityDays := req.ValidityDays
	if validityDays <= 0 {
		validityDays = 3650 // 10 years default
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               buildPkixName(&req.SubjectFields),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, validityDays),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		MaxPathLenZero:        false,
		SignatureAlgorithm:    getSignatureAlgorithm(privateKey, req.SignatureAlgorithm),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, getPublicKey(privateKey), privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, privateKey, nil
}

func (s *CAService) GenerateIntermediateCA(req *models.CreateIntermediateCARequest, parentCert *x509.Certificate, parentKey crypto.PrivateKey) (*x509.Certificate, crypto.PrivateKey, error) {
	keyAlgorithm := req.KeyAlgorithm
	if keyAlgorithm == "" {
		keyAlgorithm = models.KeyAlgorithmRSA4096 // Default for Intermediate CA
	}

	privateKey, err := generatePrivateKey(keyAlgorithm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	validityDays := req.ValidityDays
	if validityDays <= 0 {
		validityDays = 1825 // 5 years default
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               buildPkixName(&req.SubjectFields),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, validityDays),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
		SignatureAlgorithm:    getSignatureAlgorithm(parentKey, req.SignatureAlgorithm),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parentCert, getPublicKey(privateKey), parentKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, privateKey, nil
}

func (s *CAService) GenerateCertificate(req *models.CreateCertificateRequest, caCert *x509.Certificate, caKey crypto.PrivateKey) (*x509.Certificate, crypto.PrivateKey, error) {
	keyAlgorithm := req.KeyAlgorithm
	if keyAlgorithm == "" {
		keyAlgorithm = models.KeyAlgorithmECDSAP256 // Default for end-entity certificates
	}

	privateKey, err := generatePrivateKey(keyAlgorithm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	validityDays := req.ValidityDays
	if validityDays <= 0 {
		validityDays = 365 // 1 year default
	}

	var keyUsage x509.KeyUsage
	var extKeyUsage []x509.ExtKeyUsage

	switch req.Type {
	case models.CertTypeServer:
		keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case models.CertTypeClient:
		keyUsage = x509.KeyUsageDigitalSignature
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	default:
		return nil, nil, errors.New("invalid certificate type")
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               buildPkixName(&req.SubjectFields),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, validityDays),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              req.DNSNames,
		SignatureAlgorithm:    getSignatureAlgorithm(caKey, req.SignatureAlgorithm),
	}

	for _, ipStr := range req.IPAddresses {
		if ip := net.ParseIP(ipStr); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, getPublicKey(privateKey), caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, privateKey, nil
}

func (s *CAService) GenerateCRL(caCert *x509.Certificate, caKey crypto.PrivateKey, revokedCerts []models.Certificate) ([]byte, error) {
	var revokedList []pkix.RevokedCertificate

	for _, cert := range revokedCerts {
		serialNumber := new(big.Int)
		serialNumber.SetString(cert.SerialNumber, 10)

		revokedList = append(revokedList, pkix.RevokedCertificate{
			SerialNumber:   serialNumber,
			RevocationTime: *cert.RevokedAt,
		})
	}

	crlTemplate := &x509.RevocationList{
		Number:              big.NewInt(time.Now().Unix()),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().AddDate(0, 0, 7),
		RevokedCertificates: revokedList,
	}

	signer, ok := caKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create CRL: %w", err)
	}

	return crlDER, nil
}

func (s *CAService) EncryptPrivateKey(key crypto.PrivateKey) ([]byte, error) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	return s.encrypt(keyDER)
}

func (s *CAService) DecryptPrivateKey(encrypted []byte) (crypto.PrivateKey, error) {
	decrypted, err := s.decrypt(encrypted)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS8PrivateKey(decrypted)
}

func (s *CAService) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (s *CAService) decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func CertToPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

func KeyToPEM(key crypto.PrivateKey) []byte {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		})
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: der,
		})
	default:
		// Fallback to PKCS8
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		})
	}
}

func ParseCertPEM(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// PKCS#7 SignedData structure for certificate-only (degenerate) format
var (
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
)

type pkcs7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type pkcs7SignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo pkcs7EncapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos      asn1.RawValue
}

type pkcs7EncapContentInfo struct {
	EContentType asn1.ObjectIdentifier
}

// CreatePKCS7 creates a PKCS#7 (P7B) file containing the certificate chain
func CreatePKCS7(certs []*x509.Certificate) ([]byte, error) {
	if len(certs) == 0 {
		return nil, errors.New("no certificates provided")
	}

	// Build raw certificates as a SET
	var rawCerts []asn1.RawValue
	for _, cert := range certs {
		rawCerts = append(rawCerts, asn1.RawValue{FullBytes: cert.Raw})
	}

	certsBytes, err := asn1.Marshal(rawCerts)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificates: %w", err)
	}

	// Empty SET for digestAlgorithms
	emptySet, _ := asn1.Marshal([]interface{}{})

	signedData := pkcs7SignedData{
		Version:          1,
		DigestAlgorithms: asn1.RawValue{FullBytes: emptySet},
		EncapContentInfo: pkcs7EncapContentInfo{
			EContentType: oidData,
		},
		Certificates: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      certsBytes[2:], // Skip the SEQUENCE tag
		},
		SignerInfos: asn1.RawValue{FullBytes: emptySet},
	}

	signedDataBytes, err := asn1.Marshal(signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signed data: %w", err)
	}

	contentInfo := pkcs7ContentInfo{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      signedDataBytes,
		},
	}

	return asn1.Marshal(contentInfo)
}

func generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

// buildPkixName creates a pkix.Name from SubjectFields
func buildPkixName(fields *models.SubjectFields) pkix.Name {
	name := pkix.Name{
		CommonName: fields.CommonName,
	}

	if fields.Organization != "" {
		name.Organization = []string{fields.Organization}
	}
	if fields.OrganizationalUnit != "" {
		name.OrganizationalUnit = []string{fields.OrganizationalUnit}
	}
	if fields.Country != "" {
		name.Country = []string{fields.Country}
	}
	if fields.State != "" {
		name.Province = []string{fields.State}
	}
	if fields.Locality != "" {
		name.Locality = []string{fields.Locality}
	}
	if fields.StreetAddress != "" {
		name.StreetAddress = []string{fields.StreetAddress}
	}
	if fields.PostalCode != "" {
		name.PostalCode = []string{fields.PostalCode}
	}

	return name
}

// CSR Functions

// GenerateCSR creates a new Certificate Signing Request
func (s *CAService) GenerateCSR(req *models.GenerateCSRRequest) ([]byte, crypto.PrivateKey, error) {
	keyAlgorithm := req.KeyAlgorithm
	if keyAlgorithm == "" {
		keyAlgorithm = models.KeyAlgorithmECDSAP256 // Default for CSR
	}

	privateKey, err := generatePrivateKey(keyAlgorithm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	subject := buildPkixName(&req.SubjectFields)

	template := &x509.CertificateRequest{
		Subject:  subject,
		DNSNames: req.DNSNames,
	}

	// Add email to EmailAddresses if provided
	if req.EmailAddress != "" {
		template.EmailAddresses = []string{req.EmailAddress}
	}

	// Parse IP addresses
	for _, ipStr := range req.IPAddresses {
		if ip := net.ParseIP(ipStr); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return csrPEM, privateKey, nil
}

// ParseCSRPEM parses a PEM-encoded CSR
func ParseCSRPEM(pemData []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("unexpected PEM type: %s", block.Type)
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// SignCSR signs a CSR and returns a certificate
func (s *CAService) SignCSR(csr *x509.CertificateRequest, req *models.SignCSRRequest, caCert *x509.Certificate, caKey crypto.PrivateKey) (*x509.Certificate, error) {
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}

	validityDays := req.ValidityDays
	if validityDays <= 0 {
		validityDays = 365
	}

	var keyUsage x509.KeyUsage
	var extKeyUsage []x509.ExtKeyUsage

	switch req.Type {
	case models.CertTypeServer:
		keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case models.CertTypeClient:
		keyUsage = x509.KeyUsageDigitalSignature
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	default:
		return nil, errors.New("invalid certificate type")
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, validityDays),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// CSRToPEM converts a CSR to PEM format
func CSRToPEM(csr *x509.CertificateRequest) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	})
}
