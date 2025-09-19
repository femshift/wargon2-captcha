package fingerprint

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"captcha/internal/config"
	"captcha/internal/crypto"
	"captcha/internal/database"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type Validator struct {
	cfg *config.Config
	key []byte
}

func NewValidator(cfg *config.Config, key []byte) *Validator {
	return &Validator{
		cfg: cfg,
		key: key,
	}
}

func (v *Validator) ValidateFingerprint(encryptedFingerprint string) (*database.FingerprintData, error) {

	decryptedData, err := crypto.Decrypt(encryptedFingerprint, v.key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt fingerprint: %w", err)
	}

	reversedData := crypto.ReverseBytes(decryptedData)

	jsonData, err := crypto.DecodeBase64(string(reversedData))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 fingerprint: %w", err)
	}

	var fingerprint database.FingerprintData
	if err := json.Unmarshal(jsonData, &fingerprint); err != nil {
		return nil, fmt.Errorf("failed to parse fingerprint JSON: %w", err)
	}

	if err := v.validateFingerprintFields(&fingerprint); err != nil {
		return nil, fmt.Errorf("fingerprint validation failed: %w", err)
	}

	return &fingerprint, nil
}

func (v *Validator) validateFingerprintFields(fp *database.FingerprintData) error {
	if err := v.validateUserAgent(fp.UserAgent); err != nil {
		return fmt.Errorf("invalid user agent: %w", err)
	}

	if err := v.validateLanguage(fp.Language); err != nil {
		return fmt.Errorf("invalid language: %w", err)
	}

	if err := v.validatePlatform(fp.Platform); err != nil {
		return fmt.Errorf("invalid platform: %w", err)
	}

	if err := v.validateHardwareConcurrency(fp.HardwareConcurrency); err != nil {
		return fmt.Errorf("invalid hardware concurrency: %w", err)
	}

	if err := v.validateMaxTouchPoints(fp.MaxTouchPoints); err != nil {
		return fmt.Errorf("invalid max touch points: %w", err)
	}

	if err := v.validateColorDepth(fp.ColorDepth); err != nil {
		return fmt.Errorf("invalid color depth: %w", err)
	}

	if err := v.validatePixelRatio(fp.PixelRatio); err != nil {
		return fmt.Errorf("invalid pixel ratio: %w", err)
	}

	if err := v.validateTimezone(fp.Timezone); err != nil {
		return fmt.Errorf("invalid timezone: %w", err)
	}

	if err := v.validateDoNotTrack(fp.DoNotTrack); err != nil {
		return fmt.Errorf("invalid do not track: %w", err)
	}

	if err := v.validateScreenResolution(fp.ScreenResolution); err != nil {
		return fmt.Errorf("invalid screen resolution: %w", err)
	}

	if err := v.validateScreenResolution(fp.AvailableScreenResolution); err != nil {
		return fmt.Errorf("invalid available screen resolution: %w", err)
	}

	return nil
}

func (v *Validator) validateUserAgent(userAgent string) error {
	if len(userAgent) < 10 || len(userAgent) > 1000 {
		return fmt.Errorf("user agent length out of range")
	}

	patterns := []string{
		`Mozilla/\d+\.\d+`,
		`Chrome/\d+\.\d+`,
		`Safari/\d+\.\d+`,
		`Firefox/\d+\.\d+`,
		`Edge/\d+\.\d+`,
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, userAgent); matched {
			return nil
		}
	}

	return fmt.Errorf("user agent format not recognized")
}

func (v *Validator) validateLanguage(language string) error {
	if len(language) < 2 || len(language) > 10 {
		return fmt.Errorf("language format invalid")
	}

	matched, _ := regexp.MatchString(`^[a-z]{2}(-[A-Z]{2})?$`, language)
	if !matched {
		return fmt.Errorf("language code format invalid")
	}

	return nil
}

func (v *Validator) validatePlatform(platform string) error {
	validPlatforms := []string{
		"Win32", "MacIntel", "Linux x86_64", "Linux i686",
		"iPhone", "iPad", "Android", "X11",
	}

	for _, valid := range validPlatforms {
		if strings.Contains(platform, valid) {
			return nil
		}
	}

	return fmt.Errorf("platform not recognized")
}

func (v *Validator) validateHardwareConcurrency(concurrency int) error {
	if concurrency < 1 || concurrency > 128 {
		return fmt.Errorf("hardware concurrency out of range")
	}
	return nil
}

func (v *Validator) validateMaxTouchPoints(points int) error {
	if points < 0 || points > 10 {
		return fmt.Errorf("max touch points out of range")
	}
	return nil
}

func (v *Validator) validateColorDepth(depth int) error {
	validDepths := []int{8, 16, 24, 30, 32, 48}
	for _, valid := range validDepths {
		if depth == valid {
			return nil
		}
	}
	return fmt.Errorf("color depth not valid")
}

func (v *Validator) validatePixelRatio(ratio float64) error {
	if ratio < 0.5 || ratio > 5.0 {
		return fmt.Errorf("pixel ratio out of range")
	}
	return nil
}

func (v *Validator) validateTimezone(timezone string) error {
	if len(timezone) == 0 || len(timezone) > 10 {
		return fmt.Errorf("timezone length out of range")
	}

	matched, _ := regexp.MatchString(`^-?\d+$`, timezone)
	if !matched {
		return fmt.Errorf("timezone format invalid - should be numeric offset")
	}

	offset, err := strconv.Atoi(timezone)
	if err != nil {
		return fmt.Errorf("timezone not a valid number")
	}
	
	if offset < -840 || offset > 720 {
		return fmt.Errorf("timezone offset out of valid range")
	}

	return nil
}

func (v *Validator) validateDoNotTrack(dnt string) error {
	validValues := []string{"1", "0", "unspecified", "null", ""}
	for _, valid := range validValues {
		if dnt == valid {
			return nil
		}
	}
	return fmt.Errorf("do not track value invalid")
}

func (v *Validator) validateScreenResolution(resolution string) error {
	if resolution == "" {
		return fmt.Errorf("screen resolution cannot be empty")
	}

	parts := strings.Split(resolution, "x")
	if len(parts) != 2 {
		return fmt.Errorf("screen resolution format invalid")
	}

	width, err := strconv.Atoi(parts[0])
	if err != nil || width < 100 || width > 10000 {
		return fmt.Errorf("screen width out of range")
	}

	height, err := strconv.Atoi(parts[1])
	if err != nil || height < 100 || height > 10000 {
		return fmt.Errorf("screen height out of range")
	}

	return nil
} 