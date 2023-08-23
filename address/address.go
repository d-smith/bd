package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/manifoldco/promptui"
	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
	"golang.org/x/crypto/sha3"
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

	// Prompt for key id
	fmt.Println("Enter key id")
	keyIDPrompt := promptui.Prompt{
		Label: "Public Key",
	}

	keyID, err := keyIDPrompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return
	}

	// Get the public key as a DER encoding

	derPubKey, err := ecdsaClient.PublicKey(keyID, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(hex.EncodeToString(derPubKey))

	publicKey, err := ecdsaClient.ParsePublicKey(derPubKey)
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
	fmt.Println("Ethereum address: ", ethAddress)

}
