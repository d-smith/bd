package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
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

	// Generate an ECDSA key

	sessionID := tsm.GenerateSessionID()
	var keyID string
	var eg errgroup.Group
	for _, ecdsaClient := range ecdsaClients {
		ecdsaClient := ecdsaClient
		eg.Go(func() error {
			var err error
			keyID, err = ecdsaClient.KeygenWithSessionID(sessionID, "secp256k1")
			return err
		})
	}
	if err := eg.Wait(); err != nil {
		log.Fatal(err)
	}

	log.Printf("Generated key ID: %s\n", keyID)

	// Get the public key

	ecdsaClient := ecdsaClients[0]
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

	// Create an ERS key pair and ERS label
	// Here we generate the private key in the clear, but it could also be exported from an HSM

	ersPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	ersPrivateKeyBytes := x509.MarshalPKCS1PrivateKey(ersPrivateKey)

	ersPublicKey, err := x509.MarshalPKIXPublicKey(&ersPrivateKey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	ersLabel := []byte("test")

	// Collect the partial recovery data

	sessionID = tsm.GenerateSessionID()
	var partialRecoveryData = make([][]byte, len(ecdsaClients))
	for i := range ecdsaClients {
		i := i
		eg.Go(func() error {
			var err error
			r, err := ecdsaClients[i].PartialRecoveryInfo(sessionID, keyID, ersPublicKey, ersLabel)
			partialRecoveryData[i] = r[0]
			return err
		})
	}
	if err := eg.Wait(); err != nil {
		log.Fatal(err)
	}

	// Combine the partial recovery data

	recoveryData, err := tsm.RecoveryInfoCombine(partialRecoveryData, ersPublicKey, ersLabel)
	if err != nil {
		log.Fatal(err)
	}

	// Validate the combined recovery data against the ERS public key and the public ECDSA key

	publicKeyBytes, err := ecdsaClients[0].PublicKey(keyID, nil)
	if err != nil {
		log.Fatal(err)
	}

	err = tsm.RecoveryInfoValidate(recoveryData, ersPublicKey, ersLabel, publicKeyBytes)
	if err != nil {
		log.Fatal(err)
	}

	// Recover the private ECDSA key

	curveName, privateECDSAKey, masterChainCode, err := tsm.RecoverKeyECDSA(recoveryData, ersPrivateKeyBytes, ersLabel)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Curve:                      ", curveName)
	fmt.Println("Recovered private ECDSA key:", privateECDSAKey)
	fmt.Println("Recovered master chain code:", hex.EncodeToString(masterChainCode))

	// Get the EOA from the recovered key
	recoveredPubKey := privateECDSAKey.Public().(*ecdsa.PublicKey)

	msg = make([]byte, 2*32)
	recoveredPubKey.X.FillBytes(msg[0:32])
	recoveredPubKey.Y.FillBytes(msg[32:64])

	h = sha3.NewLegacyKeccak256()
	_, err = h.Write(msg)
	if err != nil {
		panic(err)
	}
	hashValue = h.Sum(nil)

	// Ethereum address is rightmost 160 bits of the hash value
	ethAddress = hex.EncodeToString(hashValue[len(hashValue)-20:])
	log.Print("Ethereum address: ", ethAddress)

}
