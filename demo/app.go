package main

import (
	"encoding/json"
	"fmt"
	"github.com/yahoo/spartan-go"
	"io/ioutil"
	"os"
)

type ConfigParams struct {
	PubKeyFile   string `json:"pubkey"`
	PrivKeyFile  string `json:"privkey"`
	URL          string `json:"url"`
	SkipVerify   bool   `json:"skip_verify"`
	CaCert       string `json:"cacert"`
	Role         string `json:"role"`
	ASPubKeyFile string `json:"as_pubkey"`
}

func main() {
	args := os.Args
	if len(args) < 2 {
		fmt.Println("Invalid number of arguments specified")
		os.Exit(1)
	}
	jsonData, err := ioutil.ReadFile(args[1])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	input := ConfigParams{}
	err = json.Unmarshal(jsonData, &input)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	tokenOptions := &spartan.TokenOptions{PubKeyFile: input.PubKeyFile,
		PrivKeyFile:        input.PrivKeyFile,
		URL:                input.URL,
		InsecureSkipVerify: input.SkipVerify,
		CaCertFile:         input.CaCert,
	}

	token, err := spartan.GetToken(input.Role, tokenOptions)
	if err != nil {
		fmt.Println("Unable to get token from AS")
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("Token received from AS: " + token)
	verifyOptions := &spartan.VerifyOptions{ASPubKeyFile: input.ASPubKeyFile,
		Role: input.Role}
	err = spartan.VerifyToken(token, verifyOptions)
	if err != nil {
		fmt.Println("verifyToken failed")
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("Token verification using AS public key succeeded")
}
