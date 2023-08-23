package main

import (
	"fmt"
	"log"
	"os"

	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
)

func main() {
	b, err := os.ReadFile("../creds.json")
	if err != nil {
		log.Fatal(err)
	}
	credentials := string(b)

	// Create ECDSA client from credentials

	tsmClient, err := tsm.NewPasswordClientFromEncoding(3, 1, credentials)
	if err != nil {
		log.Fatal(err)
	}

	ecdsaClient := tsm.NewECDSAClient(tsmClient) // ECDSA with secp256k1 curve

	// Generate ECDSA key

	keyID, err := ecdsaClient.Keygen("secp256k1")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Generated key: ID=%s\n", keyID)

}
