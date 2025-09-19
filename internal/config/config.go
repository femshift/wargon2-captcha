package config

import (
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	DBHost     string
	DBPort     int
	DBName     string
	DBUser     string
	DBPassword string
	DBSSLMode  string

	ServerPort string
	ServerHost string

	Argon2Time         uint32
	Argon2Memory       uint32
	Argon2Threads      uint8
	Argon2KeyLength    uint32
	Argon2SaltLength   int
	Argon2TargetPrefix string
	Argon2MaxSolveTime int

	ChallengeExpiryMinutes        int
	ChallengeCleanupIntervalMins  int

	AESKey                        string
	AESKeyLength                  int
	FingerprintValidationTimeout  int

	WASMFingerprintFields []string
	WASMObfuscationLevel  int

	APIRateLimitRequests     int
	APIRateLimitWindowMins   int
	APICORSOrigins           []string

	CSRFTokenLength      int
	SessionTimeoutMins   int

	LogLevel string
	LogFile  string

	DebugMode     bool
	EnableMetrics bool
}

func Load() (*Config, error) {
	godotenv.Load("config.env")

	cfg := &Config{
		DBHost:     getEnvString("DB_HOST", "localhost"),
		DBPort:     getEnvInt("DB_PORT", 5432),
		DBName:     getEnvString("DB_NAME", "captcha_db"),
		DBUser:     getEnvString("DB_USER", "postgres"),
		DBPassword: getEnvString("DB_PASSWORD", ""),
		DBSSLMode:  getEnvString("DB_SSL_MODE", "disable"),

		ServerPort: getEnvString("SERVER_PORT", "8080"),
		ServerHost: getEnvString("SERVER_HOST", "localhost"),

		Argon2Time:         uint32(getEnvInt("ARGON2_TIME", 3)),
		Argon2Memory:       uint32(getEnvInt("ARGON2_MEMORY", 65536)),
		Argon2Threads:      uint8(getEnvInt("ARGON2_THREADS", 1)),
		Argon2KeyLength:    uint32(getEnvInt("ARGON2_KEY_LENGTH", 32)),
		Argon2SaltLength:   getEnvInt("ARGON2_SALT_LENGTH", 16),
		Argon2TargetPrefix: getEnvString("ARGON2_TARGET_PREFIX", "000"),
		Argon2MaxSolveTime: getEnvInt("ARGON2_MAX_SOLVE_TIME", 6),

		ChallengeExpiryMinutes:       getEnvInt("CHALLENGE_EXPIRY_MINUTES", 5),
		ChallengeCleanupIntervalMins: getEnvInt("CHALLENGE_CLEANUP_INTERVAL_MINUTES", 10),

		AESKey:                       getEnvString("AES_KEY", ""),
		AESKeyLength:                 getEnvInt("AES_KEY_LENGTH", 32),
		FingerprintValidationTimeout: getEnvInt("FINGERPRINT_VALIDATION_TIMEOUT", 30),

		WASMFingerprintFields: getEnvStringSlice("WASM_FINGERPRINT_FIELDS", []string{
			"userAgent", "language", "platform", "hardwareConcurrency", "maxTouchPoints",
			"colorDepth", "pixelRatio", "timezone", "cookieEnabled", "doNotTrack",
			"screenResolution", "availableScreenResolution",
		}),
		WASMObfuscationLevel: getEnvInt("WASM_OBFUSCATION_LEVEL", 3),

		APIRateLimitRequests:   getEnvInt("API_RATE_LIMIT_REQUESTS", 10),
		APIRateLimitWindowMins: getEnvInt("API_RATE_LIMIT_WINDOW_MINUTES", 1),
		APICORSOrigins:         getEnvStringSlice("API_CORS_ORIGINS", []string{"*"}),

		CSRFTokenLength:    getEnvInt("CSRF_TOKEN_LENGTH", 32),
		SessionTimeoutMins: getEnvInt("SESSION_TIMEOUT_MINUTES", 30),

		LogLevel: getEnvString("LOG_LEVEL", "info"),
		LogFile:  getEnvString("LOG_FILE", "captcha.log"),

		DebugMode:     getEnvBool("DEBUG_MODE", false),
		EnableMetrics: getEnvBool("ENABLE_METRICS", true),
	}

	return cfg, nil
}

func getEnvString(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvStringSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return defaultValue
} 