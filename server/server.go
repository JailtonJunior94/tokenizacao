package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"

	"github.com/square/go-jose/v3"
)

type CreditCard struct {
	Number     string `json:"number"`
	ExpiryDate string `json:"expiryDate"`
	CVV        string `json:"cvv"`
}

func main() {
	// Gerar um novo par de chaves RSA
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Erro ao gerar a chave privada: %v\n", err)
		return
	}

	if err := savePrivateKeyToPEM(privateKey, "private_key.pem"); err != nil {
		fmt.Printf("Erro ao salvar a chave privada em arquivo: %v\n", err)
		return
	}

	publicKey := &privateKey.PublicKey
	if err := savePublicKeyToPEM(publicKey, "public_key.pem"); err != nil {
		fmt.Printf("Erro ao salvar a chave pública em arquivo: %v\n", err)
		return
	}

	// Dados do cartão de crédito
	card := CreditCard{
		Number:     "1234 5678 9012 3456",
		ExpiryDate: "06/25",
		CVV:        "123",
	}

	cardData, err := json.Marshal(card)
	if err != nil {
		fmt.Printf("Erro ao serializar os dados do cartão: %v\n", err)
		return
	}

	// Criptografar os dados do cartão
	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{
			Algorithm: jose.RSA_OAEP,
			Key:       publicKey,
		},
		(&jose.EncrypterOptions{}).
			WithType("JWT").
			WithContentType("JWT"))
	if err != nil {
		fmt.Printf("Erro ao criar o encrypter: %v\n", err)
		return
	}

	object, err := encrypter.Encrypt(cardData)
	if err != nil {
		fmt.Printf("Erro ao criptografar os dados do cartão: %v\n", err)
		return
	}

	token, err := object.CompactSerialize()
	if err != nil {
		fmt.Printf("Erro ao serializar o token: %v\n", err)
		return
	}

	fmt.Printf("Token JWE: %s\n", token)

	// Descriptografar o token
	parsedObject, err := jose.ParseEncrypted(token)
	if err != nil {
		fmt.Printf("Erro ao parsear o token: %v\n", err)
		return
	}

	decrypted, err := parsedObject.Decrypt(privateKey)
	if err != nil {
		fmt.Printf("Erro ao descriptografar o token: %v\n", err)
		return
	}

	var decryptedCard CreditCard
	err = json.Unmarshal(decrypted, &decryptedCard)
	if err != nil {
		fmt.Printf("Erro ao deserializar os dados do cartão: %v\n", err)
		return
	}

	fmt.Printf("Dados do cartão descriptografados: %+v\n", decryptedCard)

	jwksString, err := publicKeyToJWKS(publicKey)
	if err != nil {
		fmt.Printf("Erro ao obter JWKS: %v\n", err)
		return
	}

	fmt.Println("Chave pública em formato JWKS:\n", jwksString)
}

func savePrivateKeyToPEM(privateKey *rsa.PrivateKey, filename string) error {
	// Converter a chave privada para o formato PEM
	privASN1 := x509.MarshalPKCS1PrivateKey(privateKey)

	privPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privASN1,
		},
	)

	// Escrever o arquivo PEM
	return ioutil.WriteFile(filename, privPEM, 0600) // Permissões restritas
}

func savePublicKeyToPEM(publicKey *rsa.PublicKey, filename string) error {
	pubASN1, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}

	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubASN1,
		},
	)

	// Escrever o arquivo PEM
	return ioutil.WriteFile(filename, pubPEM, 0644)
}

func publicKeyToJWKS(publicKey *rsa.PublicKey) (string, error) {
	// Extrair o módulo (n) e o expoente (e) da chave pública
	modulus := publicKey.N
	exponent := big.NewInt(int64(publicKey.E))

	// Codificar em Base64 URL-safe
	modulusB64 := base64.RawURLEncoding.EncodeToString(modulus.Bytes())
	exponentB64 := base64.RawURLEncoding.EncodeToString(exponent.Bytes())

	// Montar o objeto JWKS
	jwks := map[string]interface{}{
		"kty": "RSA",
		"alg": "RS256",
		"use": "sig",
		"n":   modulusB64,
		"e":   exponentB64,
	}

	jwksJSON, err := json.Marshal(jwks)
	if err != nil {
		return "", fmt.Errorf("erro ao converter JWKS para JSON: %v", err)
	}

	return string(jwksJSON), nil
}
