package secret

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"

	cryptomodule "github.com/secret-ta/k8s-ta-internal-crypto-library"
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

const (
	secretKey  = "/var/lib/kubelet/pki/secrets.key"
	secretKey1 = "/var/lib/kubelet/pki/secrets-1.key"
	secretKey2 = "/var/lib/kubelet/pki/secrets-2.key"

	interceptorKey = "/var/lib/kubelet/pki/interceptor-publickey.pem"

	encryptedKey     = "encrypted"
	shouldDecryptKey = "should-decrypt"

	signedKey    = "signed"
	signatureKey = "signature"
)

var (
	// - node private keys
	nodePrivateKey  []byte // one secret
	nodePrivateKey2 []byte // split secret

	// - interceptor public key
	interceptorPublicKey []byte

	c = cryptomodule.NewCryptoModule(nil)
)

func init() {
	var err error

	// - single key test
	nodePrivateKey, err = c.KeyFromFile(secretKey)
	if err != nil {
		panic(wrapError("error reading single private key", err))
	}

	// - double keys test
	p1, err := c.KeyFromFile(secretKey1)
	if err != nil {
		panic(wrapError("error reading first double private key", err))
	}
	p2, err := c.KeyFromFile(secretKey2)
	if err != nil {
		panic(wrapError("error reading second double private key", err))
	}
	nodePrivateKey2, err = c.CombineKeys([][]byte{p1, p2})
	if err != nil {
		panic(wrapError("error combining double private key", err))
	}

	// - read interceptor public key
	interceptorPublicKey, err = c.KeyFromFile(interceptorKey)
	if err != nil {
		panic(wrapError("error reading interceptor public key", err))
	}
}

func wrapError(msg string, err error) string {
	return fmt.Errorf("%s: %w", msg, err).Error()
}

func process(secret *v1.Secret) *v1.Secret {
	// secret is nil then return
	if secret == nil {
		return secret
	}

	// deep copy secret
	newSecret := secret.DeepCopy()

	// annotations are nil, replace with new one
	if newSecret.Annotations == nil {
		newSecret.Annotations = map[string]string{}
	}

	// - check key 1 2
	bleh := bytes.Equal(nodePrivateKey, nodePrivateKey2)
	klog.InfoS("private key same?", "same", bleh)

	// TODO:
	// 1. whether to send message for each secret's key that there's error (verify error / encrypt error)

	// - do encrypt
	newSecret = decrypt(secret, newSecret)

	// - check hash
	secretOk := verify(newSecret)

	// - secret's signature is invalid, return empty secret
	if !secretOk {
		newSecret := secret.DeepCopy()
		for key := range newSecret.Data {
			newSecret.Data[key] = []byte{}
		}
		return newSecret
	}

	return newSecret
}

func verify(secret *v1.Secret) bool {
	// check if secret's signature should be checked, if not ignore
	if sign, signed := secret.Annotations[signedKey]; !signed || sign != "true" {
		return true
	}

	klog.InfoS("verifying secret", "name", secret.Name)

	signature, exist := secret.Annotations[signatureKey]
	if !exist {
		klog.ErrorS(nil, "secret's signature doesn't exist", "name", secret.Name)
		return false
	}

	dataByte, err := json.Marshal(secret.Data)
	if err != nil {
		klog.ErrorS(err, "failed marshaling secret", "name", secret.Name)
		return false
	}

	signatureByte, err := base64StringToByte(signature)
	if err != nil {
		klog.ErrorS(err, "malformed signature", "name", secret.Name)
		return false
	}

	ok := c.Verify(interceptorPublicKey, dataByte, signatureByte)

	klog.InfoS("verifying secret done", "name", secret.Name)

	return ok
}

func decrypt(oldSecret, newSecret *v1.Secret) *v1.Secret {
	// check if secret should be decrypted, if not ignore
	if _, encrypted := newSecret.Annotations[encryptedKey]; !encrypted {
		return oldSecret
	}
	if _, shouldDecrypt := newSecret.Annotations[shouldDecryptKey]; !shouldDecrypt {
		return oldSecret
	}

	// privatekey is nil, ignoring
	if nodePrivateKey == nil || (nodePrivateKey != nil && len(nodePrivateKey) == 0) {
		klog.ErrorS(nil, "unable to proceed decrypting secret due to nil private key", "name", newSecret.Name)
		return oldSecret
	}

	klog.InfoS("decrypting secret", "name", newSecret.Name)

	var (
		wg     sync.WaitGroup
		decErr []error
		mtx    sync.Mutex
	)
	wg.Add(len(newSecret.Data))
	for k, v := range newSecret.Data {
		go func(key string, value []byte) {
			defer func() {
				wg.Done()
			}()
			// dec, err := c.Decrypt(nodePrivateKey, value)
			dec, err := c.Decrypt(nodePrivateKey2, value)
			if err != nil {
				klog.ErrorS(err, "error when decrypting secret", "name", oldSecret.Name, "key", key)
				mtx.Lock()
				decErr = append(decErr, fmt.Errorf("error decrypting secret %s key %s err %w", oldSecret.Name, key, err))
				mtx.Unlock()
				return
			}
			newSecret.Data[key] = dec
		}(k, v)
	}
	wg.Wait()

	// - if there's any error, return old secret
	if len(decErr) > 0 {
		return oldSecret
	}

	klog.InfoS("secret decrypted", "name", newSecret.Name)

	return newSecret
}

func base64StringToByte(input string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(input)
}
