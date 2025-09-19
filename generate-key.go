package main

import (
	"fmt"
	"log"

	"captcha/internal/crypto"
)

func main() {
	key, err := crypto.GenerateAESKey()
	if err != nil {
		log.Fatalf("Failed to generate AES key: %v", err)
	}

	fmt.Println("Generated AES-256 key")
	fmt.Println("===================")
	fmt.Println()
	
	fmt.Println("1. Add this to your config.env file:")
	fmt.Printf("AES_KEY=%s\n", crypto.EncodeBase64(key))
	fmt.Println()
	
	fmt.Println("2. Replace the aesKey variable in wasm/main.go with:")
	fmt.Println("var aesKey = []byte{")
	for i, b := range key {
		if i%8 == 0 {
			fmt.Print("\t")
		}
		fmt.Printf("0x%02x, ", b)
		if (i+1)%8 == 0 {
			fmt.Println()
		}
	}
	fmt.Println("}")
} 