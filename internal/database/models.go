package database

import (
	"time"
)

type Challenge struct {
	ID         string    `db:"id" json:"id"`
	Salt       string    `db:"salt" json:"salt"`
	Difficulty uint32    `db:"difficulty" json:"difficulty"`
	Memory     uint32    `db:"memory" json:"memory"`
	Threads    uint8     `db:"threads" json:"threads"`
	KeyLen     uint32    `db:"key_len" json:"keyLen"`
	Target     string    `db:"target" json:"target"`
	CreatedAt  time.Time `db:"created_at" json:"createdAt"`
	ExpiresAt  time.Time `db:"expires_at" json:"expiresAt"`
	Solved     bool      `db:"solved" json:"solved"`
	SolvedAt   *time.Time `db:"solved_at" json:"solvedAt,omitempty"`
}

type Solution struct {
	ID          string    `db:"id" json:"id"`
	ChallengeID string    `db:"challenge_id" json:"challengeId"`
	Nonce       string    `db:"nonce" json:"nonce"`
	Hash        string    `db:"hash" json:"hash"`
	Fingerprint string    `db:"fingerprint" json:"fingerprint"`
	ClientIP    string    `db:"client_ip" json:"clientIP"`
	UserAgent   string    `db:"user_agent" json:"userAgent"`
	CreatedAt   time.Time `db:"created_at" json:"createdAt"`
	Valid       bool      `db:"valid" json:"valid"`
}

type FingerprintData struct {
	UserAgent                   string `json:"userAgent"`
	Language                    string `json:"language"`
	Platform                    string `json:"platform"`
	HardwareConcurrency         int    `json:"hardwareConcurrency"`
	MaxTouchPoints              int    `json:"maxTouchPoints"`
	ColorDepth                  int    `json:"colorDepth"`
	PixelRatio                  float64 `json:"pixelRatio"`
	Timezone                    string `json:"timezone"`
	CookieEnabled               bool   `json:"cookieEnabled"`
	DoNotTrack                  string `json:"doNotTrack"`
	ScreenResolution            string `json:"screenResolution"`
	AvailableScreenResolution   string `json:"availableScreenResolution"`
} 