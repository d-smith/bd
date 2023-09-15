package main

import (
	"encoding/hex"
	"log"
	"os"

	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
	"golang.org/x/crypto/sha3"
	"golang.org/x/sync/errgroup"
)

func main() {

	// Read credentials from file
	b, err := os.ReadFile("../creds.json")
	if err != nil {
		log.Fatal(err)
	}
	credentials := string(b)

	creds, err := tsm.DecodePasswordCredentials(credentials)
	if err != nil {
		log.Fatal(err)
	}

	// Create clients for each player

	playerCount := len(creds.URLs)
	ecdsaClients := make([]tsm.ECDSAClient, playerCount)
	for player := 0; player < playerCount; player++ {
		credsPlayer := tsm.PasswordCredentials{
			UserID:    creds.UserID,
			URLs:      []string{creds.URLs[player]},
			Passwords: []string{creds.Passwords[player]},
		}
		client, err := tsm.NewPasswordClientFromCredentials(3, 1, credsPlayer)
		if err != nil {
			log.Fatal(err)
		}
		ecdsaClients[player] = tsm.NewECDSAClient(client)
	}

	// Generate ECDSA key; must be done concurrently

	sessionID := tsm.GenerateSessionID()
	var keyID string
	eg := errgroup.Group{}
	for i := 0; i < playerCount; i++ {
		i := i
		eg.Go(func() error {
			var err error
			keyID, err = ecdsaClients[i].KeygenWithSessionID(sessionID, "secp256k1")
			return err
		})
	}
	err = eg.Wait()
	if err != nil {
		log.Fatal(err)
	}

	log.Print("key ID: ", keyID)

	ecdsaClient := ecdsaClients[0]

	// Get the public key
	pkDER, err := ecdsaClient.PublicKey(keyID, nil)
	if err != nil {
		log.Fatal(err)
	}

	log.Print("Public key: ", hex.EncodeToString(pkDER))

	publicKey, err := ecdsaClient.ParsePublicKey(pkDER)
	if err != nil {
		panic(err)
	}

	msg := make([]byte, 2*32)
	publicKey.X.FillBytes(msg[0:32])
	publicKey.Y.FillBytes(msg[32:64])

	h := sha3.NewLegacyKeccak256()
	_, err = h.Write(msg)
	if err != nil {
		panic(err)
	}
	hashValue := h.Sum(nil)

	// Ethereum address is rightmost 160 bits of the hash value
	ethAddress := hex.EncodeToString(hashValue[len(hashValue)-20:])
	log.Print("Ethereum address: ", ethAddress)

}
