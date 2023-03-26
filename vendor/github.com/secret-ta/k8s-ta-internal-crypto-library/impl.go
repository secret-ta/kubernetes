package k8stainternalcryptolibrary

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/secret-ta/k8s-ta-internal-crypto-library/shamir"
)

func (c *cryptoImpl) KeyFromFile(filename string) ([]byte, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("invalid key file")
	}
	return block.Bytes, nil
}

func (c *cryptoImpl) GeneratePublicPrivateKey() ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(c.randSource, c.keyBits)

	if err != nil {
		return nil, nil, err
	}

	publicKey := privateKey.PublicKey

	publicKeyByte := x509.MarshalPKCS1PublicKey(&publicKey)
	privateKeyByte := x509.MarshalPKCS1PrivateKey(privateKey)

	return publicKeyByte, privateKeyByte, nil
}

func (c *cryptoImpl) SplitKey(secret []byte, parts, threshold int) ([][]byte, error) {
	return shamir.Split(secret, parts, threshold)
}

func (c *cryptoImpl) CombineKeys(parts [][]byte) ([]byte, error) {
	return shamir.Combine(parts)
}

func (c *cryptoImpl) Encrypt(publickey []byte, input []byte) ([]byte, error) {
	key, err := c.parsePublicKey(publickey)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key, error %w", err)
	}

	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		key,
		input,
		nil)

	if err != nil {
		return nil, fmt.Errorf("error encrypting data, error %w", err)
	}

	return encryptedBytes, nil
}

func (c *cryptoImpl) Decrypt(privatekey []byte, input []byte) ([]byte, error) {
	key, err := c.parsePrivateKey(privatekey)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key, error %w", err)
	}

	decryptedBytes, err := key.Decrypt(rand.Reader, input, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		return nil, fmt.Errorf("error decrypting data, error %w", err)
	}

	return decryptedBytes, nil
}

func (c *cryptoImpl) Sign(privatekey []byte, input []byte) ([]byte, error) {
	key, err := c.parsePrivateKey(privatekey)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key, error %w", err)
	}

	hashedMessage, err := c.Hash(input)
	if err != nil {
		return nil, err
	}

	signature, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, hashedMessage, nil)
	if err != nil {
		return nil, fmt.Errorf("error signing input, error %w", err)
	}

	return signature, nil
}

func (c *cryptoImpl) Verify(publickey []byte, input []byte, signature []byte) bool {
	key, err := c.parsePublicKey(publickey)
	if err != nil {
		return false
	}

	hashedMessage, err := c.Hash(input)
	if err != nil {
		return false
	}

	err = rsa.VerifyPSS(key, crypto.SHA256, hashedMessage, signature, nil)

	return err == nil
}

func (c *cryptoImpl) Hash(input []byte) ([]byte, error) {
	messageHash := sha256.New()
	_, err := messageHash.Write(input)
	if err != nil {
		return nil, fmt.Errorf("error hashing input, error %w", err)
	}

	hashedMessage := messageHash.Sum(nil)
	return hashedMessage, nil
}

func (c *cryptoImpl) IsValidPrivateKey(input []byte) bool {
	key, err := c.parsePrivateKey(input)
	return err == nil && key != nil
}

func (c *cryptoImpl) IsValidPublicKey(input []byte) bool {
	key, err := c.parsePublicKey(input)
	return err == nil && key != nil
}

func (c *cryptoImpl) parsePrivateKey(input []byte) (*rsa.PrivateKey, error) {
	return x509.ParsePKCS1PrivateKey(input)
}

func (c *cryptoImpl) parsePublicKey(input []byte) (*rsa.PublicKey, error) {
	return x509.ParsePKCS1PublicKey(input)
}
