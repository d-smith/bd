package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/manifoldco/promptui"
	"gitlab.com/sepior/go-tsm-sdk/sdk/tsm"
	"golang.org/x/sync/errgroup"
)

func main() {

	// Connect to Ethereum node

	var (
		rpcEndpoint = os.Getenv("RPC_ENDPOINT")

		chainIDFromEnv = os.Getenv("CHAIN_ID")
	)

	client, err := ethclient.Dial(rpcEndpoint)
	if err != nil {
		log.Fatal(err)
	}

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
	log.Print("player count: ", playerCount)
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

	log.Print("players ready")

	keyIDPrompt := promptui.Prompt{
		Label: "Key ID",
	}

	keyID, err := keyIDPrompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return
	}

	// Get the public key
	pkDER, err := ecdsaClients[0].PublicKey(keyID, nil)
	if err != nil {
		// handle error
	}
	pk, err := ASN1ParseSecp256k1PublicKey(pkDER)
	if err != nil {
		// handle error
	}
	address := crypto.PubkeyToAddress(*pk)

	// Create a transaction
	nonce, err := client.PendingNonceAt(context.Background(), address)
	if err != nil {
		log.Fatal(err)
	}

	value := big.NewInt(100000000000000000) // in wei (0.1 eth)
	gasLimit := uint64(21000)               // in units
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	// account 0 from ganache console
	toAddress := common.HexToAddress("0x892BB2e4F6b14a2B5b82Ba8d33E5925D42D4431F")
	var data []byte
	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, data)

	chainID := new(big.Int)
	chainID, ok := chainID.SetString(chainIDFromEnv, 10)
	if !ok {
		log.Fatal("error setting chain id from env")
	}
	fmt.Println(chainID)

	signer := types.NewEIP155Signer(chainID)

	fmt.Println("sign tx")

	sessionID := tsm.GenerateSessionID()

	h := signer.Hash(tx)

	eg := errgroup.Group{}
	var partialSignature = make([][]byte, playerCount)
	for player := 0; player < playerCount; player++ {
		player := player
		eg.Go(func() error {
			var err error
			partialSignature[player], err = ecdsaClients[player].PartialSign(sessionID, keyID, nil, h[:])
			return err
		})
	}
	err = eg.Wait()
	if err != nil {
		log.Fatal(err)
	}

	signatureDER, recoveryID, err := tsm.ECDSAFinalize(partialSignature...)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Signature: %s\n", hex.EncodeToString(signatureDER))

	r, s, err := ASN1ParseSecp256k1Signature(signatureDER)
	if err != nil {
		log.Fatal(err)
	}
	signature := make([]byte, 2*32+1)
	r.FillBytes(signature[0:32])
	s.FillBytes(signature[32:64])
	signature[64] = byte(recoveryID)

	// add signature to transaction
	signedTx, err := tx.WithSignature(signer, signature)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("send tx")
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("tx sent: %s", signedTx.Hash().Hex())

}

func ASN1ParseSecp256k1PublicKey(publicKey []byte) (*ecdsa.PublicKey, error) {
	publicKeyInfo := struct {
		Raw       asn1.RawContent
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{}

	postfix, err := asn1.Unmarshal(publicKey, &publicKeyInfo)
	if err != nil || len(postfix) > 0 {
		return nil, errors.New("invalid or incomplete ASN1")
	}
	// check params

	pk, err := secp.ParsePubKey(publicKeyInfo.PublicKey.Bytes)
	if err != nil {
		return nil, err
	}
	return pk.ToECDSA(), nil
}

func ASN1ParseSecp256k1Signature(signature []byte) (r, s *big.Int, err error) {
	sig := struct {
		R *big.Int
		S *big.Int
	}{}
	postfix, err := asn1.Unmarshal(signature, &sig)
	if err != nil {
		return nil, nil, err
	}
	if len(postfix) > 0 {
		return nil, nil, errors.New("trailing bytes for ASN1 ecdsa signature")
	}
	return sig.R, sig.S, nil
}
