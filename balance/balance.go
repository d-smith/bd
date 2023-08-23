package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/manifoldco/promptui"
)

func main() {

	var (
		rpcEndpoint = os.Getenv("RPC_ENDPOINT")
	)

	client, err := ethclient.Dial(rpcEndpoint)
	if err != nil {
		log.Fatal(err)
	}

	addressPrompt := promptui.Prompt{
		Label: "Address",
	}

	address, err := addressPrompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return
	}

	//HD wallet account 0 address
	account := common.HexToAddress(address)
	balance, err := client.BalanceAt(context.Background(), account, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(balance)
}
