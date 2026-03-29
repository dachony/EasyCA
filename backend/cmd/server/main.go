package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/dachony/easyca/internal/acme"
	"github.com/dachony/easyca/internal/api"
	"github.com/dachony/easyca/internal/ca"
	"github.com/dachony/easyca/internal/middleware"
	"github.com/dachony/easyca/internal/scheduler"
	"github.com/dachony/easyca/internal/smtp"
	"github.com/dachony/easyca/internal/storage"
	"github.com/gin-gonic/gin"
)

func main() {
	dbPath := os.Getenv("DATABASE_PATH")
	if dbPath == "" {
		dbPath = "./data/easyca.db"
	}

	encryptionKey := os.Getenv("CA_ENCRYPTION_KEY")
	if encryptionKey == "" {
		log.Fatal("CA_ENCRYPTION_KEY environment variable is required")
	}

	db, err := storage.NewDatabase(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	r := gin.Default()

	// Rate limiting: 300 requests/minute per IP, burst of 60
	rateLimiter := middleware.NewRateLimiter(300, 60)
	r.Use(rateLimiter.Middleware())

	// Metrics
	metrics := middleware.NewMetrics(db)
	r.Use(metrics.Middleware())
	r.GET("/metrics", metrics.Handler())

	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = encryptionKey // fallback to encryption key
	}

	handler := api.NewHandler(db, []byte(encryptionKey), jwtSecret)
	handler.RegisterRoutes(r)

	// Initialize services
	smtpService := smtp.NewSMTPService([]byte(encryptionKey))
	caService := ca.NewCAService([]byte(encryptionKey))

	// ACME server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8443"
	}
	acmeBaseURL := os.Getenv("ACME_BASE_URL")
	if acmeBaseURL == "" {
		acmeBaseURL = "http://localhost:" + port
	}
	acmeHandler := acme.NewACMEHandler(db, caService, acmeBaseURL)
	acmeHandler.RegisterRoutes(r)

	// Start scheduler
	sched := scheduler.NewScheduler(db, smtpService, caService)
	sched.Start()

	// Handle graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Println("Shutting down...")
		sched.Stop()
		db.Close()
		os.Exit(0)
	}()

	log.Printf("Starting EasyCA server on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
