package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"syscall/js"
)

type FingerprintData struct {
	UserAgent                   string  `json:"userAgent"`
	Language                    string  `json:"language"`
	Platform                    string  `json:"platform"`
	HardwareConcurrency         int     `json:"hardwareConcurrency"`
	MaxTouchPoints              int     `json:"maxTouchPoints"`
	ColorDepth                  int     `json:"colorDepth"`
	PixelRatio                  float64 `json:"pixelRatio"`
	Timezone                    string  `json:"timezone"`
	CookieEnabled               bool    `json:"cookieEnabled"`
	DoNotTrack                  string  `json:"doNotTrack"`
	ScreenResolution            string  `json:"screenResolution"`
	AvailableScreenResolution   string  `json:"availableScreenResolution"`
}

var aesKey = []byte{
	0x36, 0x37, 0xe1, 0x93, 0x89, 0x36, 0xac, 0xc4,
	0x39, 0xf7, 0x4d, 0xec, 0x3d, 0x13, 0xee, 0x3f,
	0x1c, 0xe8, 0x57, 0x21, 0x9f, 0x83, 0xdc, 0x52,
	0x73, 0x3d, 0x97, 0x30, 0xc3, 0x24, 0xbe, 0x33,
}

func main() {
	c := make(chan struct{}, 0)

	js.Global().Set("collectFingerprint", js.FuncOf(collectFingerprint))
	js.Global().Set("encryptData", js.FuncOf(encryptData))

	<-c
}



func collectFingerprint(this js.Value, args []js.Value) interface{} {

	window := js.Global().Get("window")
	navigator := window.Get("navigator")
	screen := window.Get("screen")

	fingerprint := FingerprintData{
		UserAgent:           navigator.Get("userAgent").String(),
		Language:            navigator.Get("language").String(),
		Platform:            navigator.Get("platform").String(),
		HardwareConcurrency: navigator.Get("hardwareConcurrency").Int(),
		MaxTouchPoints:      navigator.Get("maxTouchPoints").Int(),
		ColorDepth:          screen.Get("colorDepth").Int(),
		PixelRatio:          window.Get("devicePixelRatio").Float(),
		CookieEnabled:       navigator.Get("cookieEnabled").Bool(),
	}

	date := js.Global().Get("Date").New()
	timezoneOffset := date.Call("getTimezoneOffset").Int()
	fingerprint.Timezone = fmt.Sprintf("%d", timezoneOffset)

	dnt := navigator.Get("doNotTrack")
	if dnt.Type() == js.TypeNull || dnt.Type() == js.TypeUndefined {
		fingerprint.DoNotTrack = "unspecified"
	} else {
		fingerprint.DoNotTrack = dnt.String()
	}

	fingerprint.ScreenResolution = fmt.Sprintf("%dx%d", 
		screen.Get("width").Int(), 
		screen.Get("height").Int())
	
	fingerprint.AvailableScreenResolution = fmt.Sprintf("%dx%d", 
		screen.Get("availWidth").Int(), 
		screen.Get("availHeight").Int())

	jsonData, err := json.Marshal(fingerprint)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to serialize fingerprint",
		}
	}

	b64Data := base64.StdEncoding.EncodeToString(jsonData)

	reversedData := reverseString(b64Data)

	encryptedData, err := encrypt([]byte(reversedData), aesKey)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to encrypt fingerprint",
		}
	}

	return map[string]interface{}{
		"success":     true,
		"fingerprint": encryptedData,
	}
}

func encryptData(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return map[string]interface{}{
			"success": false,
			"error":   "Data required",
		}
	}

	data := args[0].String()

	b64Data := base64.StdEncoding.EncodeToString([]byte(data))

	reversedData := reverseString(b64Data)

	encryptedData, err := encrypt([]byte(reversedData), aesKey)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   "Failed to encrypt data",
		}
	}

	return map[string]interface{}{
		"success": true,
		"data":    encryptedData,
	}
}

func encrypt(plaintext []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
} 