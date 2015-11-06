package spartan

// Package spartan provides simple API to get token from
// attestation server(AS) and verify the token

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"net/http"
	"time"
)

// TokenOptions allows client to set specific options in a GetToken call
type TokenOptions struct {
	PubKeyFile         string
	PrivKeyFile        string
	SignAlgo           string
	Url                string
	TokenType          string
	CachePath          string
	Version            string
	InsecureSkipVerify bool
	CaCertFile         string
	Expiry             time.Duration
}

// VerifyOptions allows client to set specific options in a GetToken call
type VerifyOptions struct {
	ASPubKeyFile string
	Role         string
	TokenType    string
	Ip           string
}

type TokenObj struct {
	Role    string `json:"role"`
	AsToken string `json:"astoken"`
}

type TokenResponse struct {
	Tokens []TokenObj `json:"tokens"`
}

// GetToken fetches the token from the AS for the specified role
func GetToken(role string, tokenOptions *TokenOptions) (string, error) {

	dTokenType := "as-app-req"
	dversion := "1"
	dExpiry := time.Second * 60
	pubKey, err := ioutil.ReadFile(tokenOptions.PubKeyFile)
	if err != nil {
		return "", err
	}
	privKey, err := ioutil.ReadFile(tokenOptions.PrivKeyFile)
	if err != nil {
		return "", err
	}

	pubSha := sha256.Sum256(pubKey)

	tokenType := dTokenType
	if len(tokenOptions.TokenType) > 0 {
		tokenType = tokenOptions.TokenType
	}
	version := dversion
	if len(tokenOptions.Version) > 0 {
		version = tokenOptions.Version
	}
	expiry := dExpiry
	if tokenOptions.Expiry != 0 {
		expiry = tokenOptions.Expiry
	}
	//fmt.Println(shavalHex)
	c := map[string]interface{}{
		"ver":    version,
		"type":   tokenType,
		"pubkey": string(pubKey),
		"sub":    hex.EncodeToString(pubSha[:]),
		"exp":    time.Now().Add(expiry).Unix()}

	token := jwt.New(jwt.SigningMethodES256)
	token.Claims = c

	key, err := jwt.ParseECPrivateKeyFromPEM(privKey)
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	tokenString, err := token.SignedString(key)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	certs := x509.NewCertPool()
	if tokenOptions.CaCertFile != "" {
		pemData, err := ioutil.ReadFile(tokenOptions.CaCertFile)
		if err != nil {
			return "", err
		}
		certs.AppendCertsFromPEM(pemData)
	}

	req, err := http.NewRequest("GET", tokenOptions.Url, nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-spartan-auth-token", tokenString)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: certs, InsecureSkipVerify: tokenOptions.InsecureSkipVerify},
	}
	client := &http.Client{Transport: tr, Timeout: time.Duration(5 * time.Second)}
	resp, err := client.Do(req)
	if err != nil {
		err = fmt.Errorf("Failed to connect to server")
		return "", err
	}
	//defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		body, _ := ioutil.ReadAll(resp.Body)
		tokenResp := TokenResponse{}
		json.Unmarshal(body, &tokenResp)
		if len(tokenResp.Tokens) == 0 {
			err = fmt.Errorf("Did not receive any token")
			return "", err
		}
		for _, tokenObj := range tokenResp.Tokens {
			if tokenObj.Role == role {
				return tokenObj.AsToken, nil
			}
		}
		err = fmt.Errorf("Unable to find the required role token")
		return "", err
	} else {
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Println("got failure response")
		fmt.Println(string(body[:]))
		err = fmt.Errorf("Failed to get token from attestation server")
		return string(body[:]), err

	}

}

// VerifyToken validates the token that is passed by client app to server
// It uses AS public key to validate the token signature
func VerifyToken(tokenData string, verifyOptions *VerifyOptions) error {
	dTokenType := "as-app-token"
	if verifyOptions.Role == "" {
		return fmt.Errorf("No role specified")
	}

	token, err := jwt.Parse(tokenData, func(t *jwt.Token) (interface{}, error) {
		asPubKey, err := ioutil.ReadFile(verifyOptions.ASPubKeyFile)
		if err != nil {
			return "", err
		}
		return jwt.ParseECPublicKeyFromPEM(asPubKey)
	})
	if err != nil {
		return err
	}

	if !token.Valid {
		return fmt.Errorf("Failed to validate the token")
	}
	tokenType := dTokenType
	if verifyOptions.TokenType != "" {
		tokenType = verifyOptions.TokenType
	}
	if token.Claims["type"] != tokenType {
		cTokType, _ := token.Claims["type"].(string)
		return fmt.Errorf("Invalid token type: " + cTokType)
	}
	// TODO check ip address in the token matches the request ip
	if token.Claims["role"] != verifyOptions.Role {
		cTokRole, _ := token.Claims["role"].(string)
		return fmt.Errorf("Invalid role : " + cTokRole)
	}
	return nil

}
