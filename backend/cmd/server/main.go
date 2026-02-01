package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/dachony/easyca/internal/api"
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

	handler := api.NewHandler(db, []byte(encryptionKey))
	handler.RegisterRoutes(r)

	// Initialize SMTP service and scheduler
	smtpService := smtp.NewSMTPService([]byte(encryptionKey))
	sched := scheduler.NewScheduler(db, smtpService)
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

	port := os.Getenv("PORT")
	if port == "" {
		port = "8443"
	}

	log.Printf("Starting EasyCA server on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
