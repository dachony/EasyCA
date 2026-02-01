package smtp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/dachony/easyca/internal/models"
)

type SMTPService struct {
	encryptionKey []byte
}

func NewSMTPService(encryptionKey []byte) *SMTPService {
	key := sha256.Sum256(encryptionKey)
	return &SMTPService{encryptionKey: key[:]}
}

// EncryptPassword encrypts the SMTP password
func (s *SMTPService) EncryptPassword(password string) ([]byte, error) {
	if password == "" {
		return nil, nil
	}

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

	return gcm.Seal(nonce, nonce, []byte(password), nil), nil
}

// DecryptPassword decrypts the SMTP password
func (s *SMTPService) DecryptPassword(encrypted []byte) (string, error) {
	if len(encrypted) == 0 {
		return "", nil
	}

	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// SendEmail sends an email using the configured SMTP settings
func (s *SMTPService) SendEmail(config *models.SMTPConfig, to, subject, body string) error {
	password, err := s.DecryptPassword(config.PasswordEncrypted)
	if err != nil {
		return fmt.Errorf("failed to decrypt password: %w", err)
	}

	addr := config.Host + ":" + strconv.Itoa(config.Port)

	msg := []byte(fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=\"UTF-8\"\r\n\r\n%s",
		config.FromAddress, to, subject, body,
	))

	var auth smtp.Auth
	if config.Username != "" {
		auth = smtp.PlainAuth("", config.Username, password, config.Host)
	}

	if config.TLSEnabled {
		return s.sendWithTLS(config.Host, addr, auth, config.FromAddress, to, msg)
	}

	return smtp.SendMail(addr, auth, config.FromAddress, []string{to}, msg)
}

func (s *SMTPService) sendWithTLS(host, addr string, auth smtp.Auth, from, to string, msg []byte) error {
	tlsConfig := &tls.Config{
		ServerName: host,
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		// Try STARTTLS instead
		return s.sendWithStartTLS(host, addr, auth, from, to, msg)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer client.Close()

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return err
		}
	}

	if err := client.Mail(from); err != nil {
		return err
	}

	if err := client.Rcpt(to); err != nil {
		return err
	}

	w, err := client.Data()
	if err != nil {
		return err
	}

	_, err = w.Write(msg)
	if err != nil {
		return err
	}

	err = w.Close()
	if err != nil {
		return err
	}

	return client.Quit()
}

func (s *SMTPService) sendWithStartTLS(host, addr string, auth smtp.Auth, from, to string, msg []byte) error {
	client, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer client.Close()

	tlsConfig := &tls.Config{
		ServerName: host,
	}

	if err := client.StartTLS(tlsConfig); err != nil {
		return err
	}

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return err
		}
	}

	if err := client.Mail(from); err != nil {
		return err
	}

	if err := client.Rcpt(to); err != nil {
		return err
	}

	w, err := client.Data()
	if err != nil {
		return err
	}

	_, err = w.Write(msg)
	if err != nil {
		return err
	}

	err = w.Close()
	if err != nil {
		return err
	}

	return client.Quit()
}

// SendTestEmail sends a test email to verify SMTP configuration
func (s *SMTPService) SendTestEmail(config *models.SMTPConfig, to string) error {
	subject := "EasyCA - Test Email"
	body := `
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; }
        .header { background: #4f46e5; color: white; padding: 20px; border-radius: 8px 8px 0 0; }
        .content { background: #f3f4f6; padding: 20px; border-radius: 0 0 8px 8px; }
        .success { color: #059669; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>EasyCA</h1>
        </div>
        <div class="content">
            <p class="success">SMTP configuration is working correctly!</p>
            <p>This is a test email from your EasyCA certificate management system.</p>
            <p>Sent at: ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
        </div>
    </div>
</body>
</html>
`
	return s.SendEmail(config, to, subject, body)
}

// SendExpiryWarning sends a certificate expiry warning email
func (s *SMTPService) SendExpiryWarning(config *models.SMTPConfig, to string, certName string, expiryDate time.Time, daysRemaining int, certType string) error {
	subject := fmt.Sprintf("EasyCA - %s Expiring in %d Days", certType, daysRemaining)

	urgencyColor := "#f59e0b" // warning yellow
	if daysRemaining <= 7 {
		urgencyColor = "#ef4444" // danger red
	}

	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; }
        .header { background: %s; color: white; padding: 20px; border-radius: 8px 8px 0 0; }
        .content { background: #f3f4f6; padding: 20px; border-radius: 0 0 8px 8px; }
        .warning { font-size: 24px; font-weight: bold; margin-bottom: 20px; }
        .details { background: white; padding: 15px; border-radius: 4px; margin: 15px 0; }
        .details p { margin: 5px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>EasyCA - Certificate Expiry Warning</h1>
        </div>
        <div class="content">
            <p class="warning">%s is expiring soon!</p>
            <div class="details">
                <p><strong>Type:</strong> %s</p>
                <p><strong>Name:</strong> %s</p>
                <p><strong>Expiry Date:</strong> %s</p>
                <p><strong>Days Remaining:</strong> %d</p>
            </div>
            <p>Please take action to renew or replace this %s before it expires.</p>
        </div>
    </div>
</body>
</html>
`, urgencyColor, certName, certType, certName, expiryDate.Format("2006-01-02 15:04:05"), daysRemaining, strings.ToLower(certType))

	return s.SendEmail(config, to, subject, body)
}

// SendIssuanceNotification sends a notification when a certificate is issued
func (s *SMTPService) SendIssuanceNotification(config *models.SMTPConfig, to string, certName string, certType string, expiryDate time.Time) error {
	subject := fmt.Sprintf("EasyCA - New %s Issued: %s", certType, certName)

	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; }
        .header { background: #059669; color: white; padding: 20px; border-radius: 8px 8px 0 0; }
        .content { background: #f3f4f6; padding: 20px; border-radius: 0 0 8px 8px; }
        .success { color: #059669; font-size: 24px; font-weight: bold; }
        .details { background: white; padding: 15px; border-radius: 4px; margin: 15px 0; }
        .details p { margin: 5px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>EasyCA - Certificate Issued</h1>
        </div>
        <div class="content">
            <p class="success">New %s issued successfully!</p>
            <div class="details">
                <p><strong>Type:</strong> %s</p>
                <p><strong>Name:</strong> %s</p>
                <p><strong>Valid Until:</strong> %s</p>
                <p><strong>Issued At:</strong> %s</p>
            </div>
        </div>
    </div>
</body>
</html>
`, certType, certType, certName, expiryDate.Format("2006-01-02"), time.Now().Format("2006-01-02 15:04:05"))

	return s.SendEmail(config, to, subject, body)
}

// SendRevocationNotification sends a notification when a certificate is revoked
func (s *SMTPService) SendRevocationNotification(config *models.SMTPConfig, to string, certName string, reason string) error {
	subject := fmt.Sprintf("EasyCA - Certificate Revoked: %s", certName)

	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        .container { max-width: 600px; margin: 0 auto; }
        .header { background: #ef4444; color: white; padding: 20px; border-radius: 8px 8px 0 0; }
        .content { background: #f3f4f6; padding: 20px; border-radius: 0 0 8px 8px; }
        .warning { color: #ef4444; font-size: 24px; font-weight: bold; }
        .details { background: white; padding: 15px; border-radius: 4px; margin: 15px 0; }
        .details p { margin: 5px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>EasyCA - Certificate Revoked</h1>
        </div>
        <div class="content">
            <p class="warning">Certificate has been revoked!</p>
            <div class="details">
                <p><strong>Certificate:</strong> %s</p>
                <p><strong>Revocation Reason:</strong> %s</p>
                <p><strong>Revoked At:</strong> %s</p>
            </div>
            <p>This certificate is no longer valid and should not be trusted.</p>
        </div>
    </div>
</body>
</html>
`, certName, reason, time.Now().Format("2006-01-02 15:04:05"))

	return s.SendEmail(config, to, subject, body)
}
