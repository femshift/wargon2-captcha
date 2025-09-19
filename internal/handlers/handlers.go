package handlers

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"captcha/internal/argon2"
	"captcha/internal/config"
	"captcha/internal/fingerprint"
)

type Handler struct {
	cfg               *config.Config
	argon2Service     *argon2.Service
	fingerprintValidator *fingerprint.Validator
	aesKey            []byte
}

func NewHandler(cfg *config.Config, argon2Service *argon2.Service, fingerprintValidator *fingerprint.Validator, aesKey []byte) *Handler {
	return &Handler{
		cfg:               cfg,
		argon2Service:     argon2Service,
		fingerprintValidator: fingerprintValidator,
		aesKey:            aesKey,
	}
}

type ChallengeResponse struct {
	Challenge interface{} `json:"challenge"`
}

type VerifyRequest struct {
	ChallengeID string `json:"challengeId"`
	Nonce       string `json:"nonce"`
	Hash        string `json:"hash"`
	Fingerprint string `json:"fingerprint"`
}

type VerifyResponse struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message,omitempty"`
}

func (h *Handler) ChallengeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	challenge, err := h.argon2Service.GenerateChallenge()
	if err != nil {
		http.Error(w, "Failed to generate challenge", http.StatusInternalServerError)
		return
	}

	response := ChallengeResponse{
		Challenge: challenge,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) VerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	clientIP := h.getClientIP(r)
	userAgent := r.Header.Get("User-Agent")

	fingerprintData, err := h.fingerprintValidator.ValidateFingerprint(req.Fingerprint)
	if err != nil {
		response := VerifyResponse{
			Valid:   false,
			Message: "Fingerprint validation failed",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	fingerprintJSON, err := json.Marshal(fingerprintData)
	if err != nil {
		http.Error(w, "Failed to serialize fingerprint", http.StatusInternalServerError)
		return
	}

	solution, err := h.argon2Service.VerifySolution(
		req.ChallengeID,
		req.Nonce,
		req.Hash,
		string(fingerprintJSON),
		clientIP,
		userAgent,
	)

	if err != nil {
		response := VerifyResponse{
			Valid:   false,
			Message: fmt.Sprintf("Verification failed: %s", err.Error()),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	response := VerifyResponse{
		Valid: solution.Valid,
	}

	if solution.Valid {
		response.Message = "Captcha solved successfully"
	} else {
		response.Message = "Invalid solution"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) HealthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := map[string]interface{}{
		"status": "healthy",
		"service": "captcha-service",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) getClientIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		if net.ParseIP(realIP) != nil {
			return realIP
		}
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return ip
} 