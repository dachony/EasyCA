package middleware

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/dachony/easyca/internal/storage"
	"github.com/gin-gonic/gin"
)

type Metrics struct {
	mu             sync.RWMutex
	requestCount   map[string]int64
	requestLatency map[string]float64
	statusCounts   map[int]int64
	db             *storage.Database
}

func NewMetrics(db *storage.Database) *Metrics {
	return &Metrics{
		requestCount:   make(map[string]int64),
		requestLatency: make(map[string]float64),
		statusCounts:   make(map[int]int64),
		db:             db,
	}
}

func (m *Metrics) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		duration := time.Since(start).Seconds()

		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}

		m.mu.Lock()
		m.requestCount[path]++
		m.requestLatency[path] += duration
		m.statusCounts[c.Writer.Status()]++
		m.mu.Unlock()
	}
}

func (m *Metrics) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		m.mu.RLock()
		reqCount := make(map[string]int64)
		reqLatency := make(map[string]float64)
		statusCounts := make(map[int]int64)
		for k, v := range m.requestCount {
			reqCount[k] = v
		}
		for k, v := range m.requestLatency {
			reqLatency[k] = v
		}
		for k, v := range m.statusCounts {
			statusCounts[k] = v
		}
		m.mu.RUnlock()

		// Build Prometheus text format
		var output string

		// Request counts per path
		output += "# HELP easyca_http_requests_total Total HTTP requests\n"
		output += "# TYPE easyca_http_requests_total counter\n"
		for path, count := range reqCount {
			output += fmt.Sprintf("easyca_http_requests_total{path=\"%s\"} %d\n", path, count)
		}

		// Request latency per path
		output += "# HELP easyca_http_request_duration_seconds Total request duration\n"
		output += "# TYPE easyca_http_request_duration_seconds counter\n"
		for path, latency := range reqLatency {
			output += fmt.Sprintf("easyca_http_request_duration_seconds{path=\"%s\"} %.6f\n", path, latency)
		}

		// Status code counts
		output += "# HELP easyca_http_responses_total Total HTTP responses by status\n"
		output += "# TYPE easyca_http_responses_total counter\n"
		for status, count := range statusCounts {
			output += fmt.Sprintf("easyca_http_responses_total{status=\"%d\"} %d\n", status, count)
		}

		// Certificate stats from DB
		if m.db != nil {
			output += m.getCertificateMetrics()
		}

		c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(output))
	}
}

func (m *Metrics) getCertificateMetrics() string {
	var output string

	// CA counts
	cas, err := m.db.ListCAs()
	if err == nil {
		rootCount := 0
		intermediateCount := 0
		for _, ca := range cas {
			if ca.Type == "root" {
				rootCount++
			} else {
				intermediateCount++
			}
		}
		output += "# HELP easyca_cas_total Total certificate authorities\n"
		output += "# TYPE easyca_cas_total gauge\n"
		output += fmt.Sprintf("easyca_cas_total{type=\"root\"} %d\n", rootCount)
		output += fmt.Sprintf("easyca_cas_total{type=\"intermediate\"} %d\n", intermediateCount)
	}

	// Certificate counts
	certs, err := m.db.ListCertificates()
	if err == nil {
		valid := 0
		revoked := 0
		expired := 0
		now := time.Now()
		for _, cert := range certs {
			if cert.RevokedAt != nil {
				revoked++
			} else if cert.NotAfter.Before(now) {
				expired++
			} else {
				valid++
			}
		}
		output += "# HELP easyca_certificates_total Total certificates\n"
		output += "# TYPE easyca_certificates_total gauge\n"
		output += fmt.Sprintf("easyca_certificates_total{status=\"valid\"} %d\n", valid)
		output += fmt.Sprintf("easyca_certificates_total{status=\"revoked\"} %d\n", revoked)
		output += fmt.Sprintf("easyca_certificates_total{status=\"expired\"} %d\n", expired)

		// Expiring soon (30 days)
		expiringSoon := 0
		for _, cert := range certs {
			if cert.RevokedAt == nil && cert.NotAfter.After(now) && cert.NotAfter.Before(now.AddDate(0, 0, 30)) {
				expiringSoon++
			}
		}
		output += "# HELP easyca_certificates_expiring_soon Certificates expiring within 30 days\n"
		output += "# TYPE easyca_certificates_expiring_soon gauge\n"
		output += fmt.Sprintf("easyca_certificates_expiring_soon %d\n", expiringSoon)
	}

	// User counts
	users, err := m.db.ListUsers()
	if err == nil {
		output += "# HELP easyca_users_total Total users\n"
		output += "# TYPE easyca_users_total gauge\n"
		output += fmt.Sprintf("easyca_users_total %d\n", len(users))
	}

	return output
}
