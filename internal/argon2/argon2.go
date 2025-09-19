package argon2

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"captcha/internal/config"
	"captcha/internal/crypto"
	"captcha/internal/database"
	"golang.org/x/crypto/argon2"
)

type Service struct {
	cfg *config.Config
	db  *database.DB
}

func NewService(cfg *config.Config, db *database.DB) *Service {
	return &Service{
		cfg: cfg,
		db:  db,
	}
}

func (s *Service) GenerateChallenge() (*database.Challenge, error) {
	salt := make([]byte, s.cfg.Argon2SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	challengeID, err := crypto.GenerateRandomBytes(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate challenge ID: %w", err)
	}

	challenge := &database.Challenge{
		ID:         hex.EncodeToString(challengeID),
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Difficulty: s.cfg.Argon2Time,
		Memory:     s.cfg.Argon2Memory,
		Threads:    s.cfg.Argon2Threads,
		KeyLen:     s.cfg.Argon2KeyLength,
		Target:     s.cfg.Argon2TargetPrefix,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(time.Duration(s.cfg.ChallengeExpiryMinutes) * time.Minute),
	}

	if err := s.db.CreateChallenge(challenge); err != nil {
		return nil, fmt.Errorf("failed to store challenge: %w", err)
	}

	return challenge, nil
}

func (s *Service) VerifySolution(challengeID, nonce, hash string, fingerprint string, clientIP, userAgent string) (*database.Solution, error) {
	challenge, err := s.db.GetChallenge(challengeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get challenge: %w", err)
	}

	if challenge == nil {
		return nil, fmt.Errorf("challenge not found")
	}

	if time.Now().After(challenge.ExpiresAt) {
		return nil, fmt.Errorf("challenge expired")
	}

	if challenge.Solved {
		return nil, fmt.Errorf("challenge already solved")
	}

	valid, err := s.verifySolution(challenge, nonce, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to verify solution: %w", err)
	}

	solutionID, err := crypto.GenerateRandomBytes(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate solution ID: %w", err)
	}

	solution := &database.Solution{
		ID:          hex.EncodeToString(solutionID),
		ChallengeID: challengeID,
		Nonce:       nonce,
		Hash:        hash,
		Fingerprint: fingerprint,
		ClientIP:    clientIP,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
		Valid:       valid,
	}

	if err := s.db.CreateSolution(solution); err != nil {
		return nil, fmt.Errorf("failed to store solution: %w", err)
	}

	if valid {
		if err := s.db.MarkChallengeSolved(challengeID); err != nil {
			return nil, fmt.Errorf("failed to mark challenge as solved: %w", err)
		}
	}

	return solution, nil
}

func (s *Service) verifySolution(challenge *database.Challenge, nonce, providedHash string) (bool, error) {
	salt, err := base64.StdEncoding.DecodeString(challenge.Salt)
	if err != nil {
		return false, fmt.Errorf("failed to decode salt: %w", err)
	}

	inputData := challenge.Salt + nonce

	hash := argon2.IDKey(
		[]byte(inputData),
		salt,
		challenge.Difficulty,
		challenge.Memory,
		challenge.Threads,
		challenge.KeyLen,
	)

	computedHash := hex.EncodeToString(hash)

	return computedHash == providedHash && s.hasValidPrefix(computedHash, challenge.Target), nil
}

func (s *Service) hasValidPrefix(hash, prefix string) bool {
	return strings.HasPrefix(hash, prefix)
}

func (s *Service) EstimateSolveTime() time.Duration {
	prefixLength := len(s.cfg.Argon2TargetPrefix)
	estimatedAttempts := 1 << (prefixLength * 4)

	hashesPerSecond := 100
	estimatedSeconds := estimatedAttempts / hashesPerSecond

	maxSeconds := s.cfg.Argon2MaxSolveTime
	if estimatedSeconds > maxSeconds {
		estimatedSeconds = maxSeconds
	}

	return time.Duration(estimatedSeconds) * time.Second
} 