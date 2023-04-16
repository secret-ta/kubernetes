package k8stainternalcryptolibrary

import (
	"crypto/rand"
	"io"
)

type (
	CryptoModule interface {
		// - key related
		GeneratePublicPrivateKey() (public, private []byte, err error)
		SplitKey(secret []byte, parts, threshold int) (keys [][]byte, err error)
		CombineKeys(parts [][]byte) (key []byte, err error)
		KeyFromFile(filename string) (key []byte, err error)
		CustomKeyFromFile(filename string) (key []byte, err error)
		IsValidPublicKey(input []byte) bool
		IsValidPrivateKey(input []byte) bool

		// - encrypt / decrypt
		Encrypt(publickey []byte, input []byte) (output []byte, err error)
		Decrypt(privatekey []byte, input []byte) (output []byte, err error)

		// - sign / verify
		Sign(privatekey []byte, input []byte) (signature []byte, err error)
		Verify(publickey []byte, input []byte, signature []byte) (valid bool)

		// - hash using SHA256
		Hash(input []byte) (hash []byte, err error)
	}

	Option struct {
		RandomSource io.Reader
		KeyBits      int
	}

	cryptoImpl struct {
		randSource io.Reader
		keyBits    int
	}
)

func NewCryptoModule(opt *Option) CryptoModule {
	if opt == nil {
		opt = &Option{}
	}
	if opt.KeyBits <= 0 {
		opt.KeyBits = 2048
	}
	if opt.RandomSource == nil {
		opt.RandomSource = rand.Reader
	}

	return &cryptoImpl{
		keyBits:    opt.KeyBits,
		randSource: opt.RandomSource,
	}
}
