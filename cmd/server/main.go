package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"captcha/internal/argon2"
	"captcha/internal/config"
	"captcha/internal/crypto"
	"captcha/internal/database"
	"captcha/internal/fingerprint"
	"captcha/internal/handlers"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"golang.org/x/time/rate"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	db, err := database.NewDB(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	var aesKey []byte
	if cfg.AESKey != "" {
		aesKey, err = crypto.DecodeBase64(cfg.AESKey)
		if err != nil {
			log.Fatalf("Failed to decode configured AES key: %v", err)
		}
		if len(aesKey) != 32 {
			log.Fatalf("AES key must be exactly 32 bytes, got %d bytes", len(aesKey))
		}
		log.Println("Using configured AES key")
	} else {
		aesKey, err = crypto.GenerateAESKey()
		if err != nil {
			log.Fatalf("Failed to generate AES key: %v", err)
		}
		log.Printf("Generated random AES key: %s", crypto.EncodeBase64(aesKey))
		log.Println("WARNING: Using random AES key. Set AES_KEY in config.env for production!")
	}

	argon2Service := argon2.NewService(cfg, db)
	fingerprintValidator := fingerprint.NewValidator(cfg, aesKey)

	handler := handlers.NewHandler(cfg, argon2Service, fingerprintValidator, aesKey)

	router := mux.NewRouter()

	api := router.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/challenge", handler.ChallengeHandler).Methods("GET")
	api.HandleFunc("/verify", handler.VerifyHandler).Methods("POST")
	api.HandleFunc("/health", handler.HealthHandler).Methods("GET")

	router.PathPrefix("/").Handler(http.FileServer(http.Dir("./web/")))

	c := cors.New(cors.Options{
		AllowedOrigins: cfg.APICORSOrigins,
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders: []string{"*"},
		AllowCredentials: true,
	})

	rateLimiter := rate.NewLimiter(
		rate.Every(time.Duration(cfg.APIRateLimitWindowMins)*time.Minute/time.Duration(cfg.APIRateLimitRequests)),
		cfg.APIRateLimitRequests,
	)

	finalHandler := rateLimitMiddleware(rateLimiter)(c.Handler(router))

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%s", cfg.ServerHost, cfg.ServerPort),
		Handler: finalHandler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go startCleanupRoutine(db, cfg)

	log.Printf("Captcha server starting on %s:%s", cfg.ServerHost, cfg.ServerPort)
	log.Printf("Database: %s:%d/%s", cfg.DBHost, cfg.DBPort, cfg.DBName)
	log.Printf("Argon2 Config: time=%d, memory=%d, threads=%d, target=%s",
		cfg.Argon2Time, cfg.Argon2Memory, cfg.Argon2Threads, cfg.Argon2TargetPrefix)

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}

func rateLimitMiddleware(limiter *rate.Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow() {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func startCleanupRoutine(db *database.DB, cfg *config.Config) {
	ticker := time.NewTicker(time.Duration(cfg.ChallengeCleanupIntervalMins) * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		log.Println("Running cleanup routine...")

		if err := db.CleanupExpiredChallenges(); err != nil {
			log.Printf("Failed to cleanup expired challenges: %v", err)
		}

		if err := db.CleanupOldSolutions(24 * time.Hour); err != nil {
			log.Printf("Failed to cleanup old solutions: %v", err)
		}

		log.Println("Cleanup routine completed")
	}
} 