package scheduler

import (
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/dachony/easyca/internal/models"
	"github.com/dachony/easyca/internal/smtp"
	"github.com/dachony/easyca/internal/storage"
)

type Scheduler struct {
	db          *storage.Database
	smtpService *smtp.SMTPService
	stopChan    chan struct{}
}

func NewScheduler(db *storage.Database, smtpService *smtp.SMTPService) *Scheduler {
	return &Scheduler{
		db:          db,
		smtpService: smtpService,
		stopChan:    make(chan struct{}),
	}
}

// Start begins the scheduler to check for expiring certificates daily
func (s *Scheduler) Start() {
	go s.run()
	log.Println("Certificate expiry notification scheduler started")
}

// Stop stops the scheduler
func (s *Scheduler) Stop() {
	close(s.stopChan)
	log.Println("Certificate expiry notification scheduler stopped")
}

func (s *Scheduler) run() {
	// Run immediately on startup
	s.checkExpiringCertificates()

	// Then run daily at midnight
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.checkExpiringCertificates()
		case <-s.stopChan:
			return
		}
	}
}

// CheckNow runs an immediate check (useful for testing)
func (s *Scheduler) CheckNow() {
	s.checkExpiringCertificates()
}

func (s *Scheduler) checkExpiringCertificates() {
	log.Println("Running certificate expiry check...")

	// Get SMTP config
	smtpConfig, err := s.db.GetSMTPConfig()
	if err != nil {
		log.Printf("Failed to get SMTP config: %v", err)
		return
	}

	if smtpConfig == nil || !smtpConfig.Enabled {
		log.Println("SMTP not configured or disabled, skipping notifications")
		return
	}

	// Get notification settings
	settings, err := s.db.GetNotificationSettings()
	if err != nil {
		log.Printf("Failed to get notification settings: %v", err)
		return
	}

	// Parse warning days
	warningDays := parseWarningDays(settings.ExpiryWarningDays)
	if len(warningDays) == 0 {
		log.Println("No warning days configured")
		return
	}

	// Get the maximum days to check
	maxDays := warningDays[0]
	for _, d := range warningDays {
		if d > maxDays {
			maxDays = d
		}
	}

	// Check certificates
	s.checkCertificates(smtpConfig, warningDays, maxDays)

	// Check CAs
	s.checkCAs(smtpConfig, warningDays, maxDays)

	log.Println("Certificate expiry check completed")
}

func (s *Scheduler) checkCertificates(smtpConfig *models.SMTPConfig, warningDays []int, maxDays int) {
	certs, err := s.db.GetExpiringCertificates(maxDays)
	if err != nil {
		log.Printf("Failed to get expiring certificates: %v", err)
		return
	}

	for _, cert := range certs {
		daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)

		// Check if this matches any warning day
		shouldNotify := false
		for _, day := range warningDays {
			if daysRemaining <= day && daysRemaining > day-1 {
				shouldNotify = true
				break
			}
		}

		if !shouldNotify {
			continue
		}

		// Check if we already sent a notification for this day
		if s.alreadySentNotification(cert.ID, "expiry_warning", daysRemaining) {
			continue
		}

		// Get recipients
		recipients, err := s.db.GetRecipientsForCertificate(cert.ID, cert.CAID)
		if err != nil {
			log.Printf("Failed to get recipients for certificate %s: %v", cert.ID, err)
			continue
		}

		for _, recipient := range recipients {
			err := s.smtpService.SendExpiryWarning(smtpConfig, recipient.Email, cert.CommonName, cert.NotAfter, daysRemaining, "Certificate")

			logEntry := &models.NotificationLog{
				CertificateID:    &cert.ID,
				NotificationType: "expiry_warning",
				RecipientEmail:   recipient.Email,
				DaysUntilExpiry:  &daysRemaining,
				SentAt:           time.Now(),
				Status:           "sent",
			}

			if err != nil {
				log.Printf("Failed to send expiry warning to %s for cert %s: %v", recipient.Email, cert.CommonName, err)
				logEntry.Status = "failed"
				errMsg := err.Error()
				logEntry.ErrorMessage = &errMsg
			} else {
				log.Printf("Sent expiry warning to %s for certificate %s (%d days remaining)", recipient.Email, cert.CommonName, daysRemaining)
			}

			s.db.AddNotificationLog(logEntry)
		}
	}
}

func (s *Scheduler) checkCAs(smtpConfig *models.SMTPConfig, warningDays []int, maxDays int) {
	cas, err := s.db.GetExpiringCAs(maxDays)
	if err != nil {
		log.Printf("Failed to get expiring CAs: %v", err)
		return
	}

	for _, ca := range cas {
		daysRemaining := int(time.Until(ca.NotAfter).Hours() / 24)

		// Check if this matches any warning day
		shouldNotify := false
		for _, day := range warningDays {
			if daysRemaining <= day && daysRemaining > day-1 {
				shouldNotify = true
				break
			}
		}

		if !shouldNotify {
			continue
		}

		// Check if we already sent a notification for this day
		if s.alreadySentNotification(ca.ID, "ca_expiry_warning", daysRemaining) {
			continue
		}

		// Get global recipients + CA-specific recipients
		recipients, err := s.db.GetRecipientsForCertificate("", ca.ID)
		if err != nil {
			log.Printf("Failed to get recipients for CA %s: %v", ca.ID, err)
			continue
		}

		for _, recipient := range recipients {
			err := s.smtpService.SendExpiryWarning(smtpConfig, recipient.Email, ca.Name, ca.NotAfter, daysRemaining, "Certificate Authority")

			logEntry := &models.NotificationLog{
				CAID:             &ca.ID,
				NotificationType: "ca_expiry_warning",
				RecipientEmail:   recipient.Email,
				DaysUntilExpiry:  &daysRemaining,
				SentAt:           time.Now(),
				Status:           "sent",
			}

			if err != nil {
				log.Printf("Failed to send CA expiry warning to %s for %s: %v", recipient.Email, ca.Name, err)
				logEntry.Status = "failed"
				errMsg := err.Error()
				logEntry.ErrorMessage = &errMsg
			} else {
				log.Printf("Sent CA expiry warning to %s for %s (%d days remaining)", recipient.Email, ca.Name, daysRemaining)
			}

			s.db.AddNotificationLog(logEntry)
		}
	}
}

func (s *Scheduler) alreadySentNotification(entityID, notificationType string, daysRemaining int) bool {
	// Check notification log to avoid duplicate notifications
	logs, err := s.db.GetNotificationLogs(100)
	if err != nil {
		return false
	}

	today := time.Now().Truncate(24 * time.Hour)

	for _, log := range logs {
		// Check if sent today
		if log.SentAt.Truncate(24*time.Hour) != today {
			continue
		}

		// Check if same type and entity
		if log.NotificationType != notificationType {
			continue
		}

		if log.CertificateID != nil && *log.CertificateID == entityID {
			return true
		}

		if log.CAID != nil && *log.CAID == entityID {
			return true
		}
	}

	return false
}

func parseWarningDays(daysStr string) []int {
	var days []int
	for _, s := range strings.Split(daysStr, ",") {
		s = strings.TrimSpace(s)
		if d, err := strconv.Atoi(s); err == nil && d > 0 {
			days = append(days, d)
		}
	}
	return days
}
