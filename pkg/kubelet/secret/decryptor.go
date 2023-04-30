package secret

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	cryptomodule "github.com/secret-ta/k8s-ta-internal-crypto-library"
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

const (
	secretKey = "/var/lib/kubelet/pki/secrets.key"

	interceptorKey = "/var/lib/kubelet/pki/interceptor-publickey.pem"

	encryptedKey     = "encrypted"
	shouldDecryptKey = "should-decrypt"
	decryptedKey     = "decrypted"

	signedKey    = "signed"
	signatureKey = "signature"
)

var (
	// - node private key
	nodePrivateKey []byte

	// - interceptor public key
	interceptorPublicKey []byte

	c = cryptomodule.NewCryptoModule(nil)
)

func init() {
	var err error

	// - double combined key test
	nodePrivateKey, err = c.CustomKeyFromFile(secretKey)
	if err != nil {
		panic(wrapError("error reading custom private key", err))
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

func process(secret *v1.Secret) (*v1.Secret, error) {
	// secret is nil then return
	if secret == nil {
		return secret, nil
	}

	// deep copy secret
	newSecret := secret.DeepCopy()

	// annotations are nil, replace with new one
	if newSecret.Annotations == nil {
		newSecret.Annotations = map[string]string{}
	}

	// // - check key 1 2
	// bleh := bytes.Equal(nodePrivateKey, nodePrivateKey2)
	// klog.InfoS("private key same?", "same", bleh)

	// // - check key 1 c
	// bleh = bytes.Equal(nodePrivateKey, nodePrivateCombinedKey)
	// klog.InfoS("[2] private key same?", "same", bleh)

	// - do encrypt
	newSecret, err := decrypt(secret, newSecret)
	if err != nil {
		return nil, err
	}

	// - check hash
	secretOk, err := verify(newSecret)
	if err != nil {
		return nil, fmt.Errorf("failed verifying secret due to error, error %w", err)
	}

	// - secret's signature is invalid, return empty secret
	if !secretOk {
		return nil, fmt.Errorf("integrity check for secret %s failed", newSecret.Name)
	}

	return newSecret, nil
}

func verify(secret *v1.Secret) (bool, error) {
	// check if secret's signature should be checked, if not ignore
	if sign, signed := secret.Annotations[signedKey]; !signed || sign != "true" {
		return true, nil
	}

	klog.InfoS("verifying secret", "name", secret.Name)
	start := time.Now()

	signature, exist := secret.Annotations[signatureKey]
	if !exist {
		klog.ErrorS(nil, "secret's signature doesn't exist", "name", secret.Name)
		return false, errors.New("signature doesn't exist")
	}

	dataByte, err := json.Marshal(secret.Data)
	if err != nil {
		klog.ErrorS(err, "failed marshaling secret", "name", secret.Name)
		return false, fmt.Errorf("failed marshaling secret, error %w", err)
	}

	signatureByte, err := base64StringToByte(signature)
	if err != nil {
		klog.ErrorS(err, "malformed signature", "name", secret.Name)
		return false, fmt.Errorf("malformed signature, error %w", err)
	}

	ok := c.Verify(interceptorPublicKey, dataByte, signatureByte)

	klog.InfoS("verifying secret done", "name", secret.Name, "elapsed", time.Since(start))

	return ok, nil
}

func decrypt(oldSecret, newSecret *v1.Secret) (*v1.Secret, error) {
	// check if secret should be decrypted, if not ignore
	if _, decrypted := newSecret.Annotations[decryptedKey]; decrypted {
		klog.InfoS("secret already decrypted", "name", newSecret.Name)

		return oldSecret, nil
	}
	if _, encrypted := newSecret.Annotations[encryptedKey]; !encrypted {
		return oldSecret, nil
	}
	if _, shouldDecrypt := newSecret.Annotations[shouldDecryptKey]; !shouldDecrypt {
		return oldSecret, nil
	}

	// privatekey is nil, ignoring
	if nodePrivateKey == nil || (nodePrivateKey != nil && len(nodePrivateKey) == 0) {
		klog.ErrorS(nil, "unable to proceed decrypting secret due to nil private key", "name", newSecret.Name)
		return nil, errors.New("malformed private key")
	}

	klog.InfoS("decrypting secret", "name", newSecret.Name)
	start := time.Now()

	var (
		wg     sync.WaitGroup
		decErr []string
		mtx    sync.Mutex
	)
	wg.Add(len(newSecret.Data))
	for k := range newSecret.Data {
		go func(key string) {
			value := newSecret.Data[key]
			defer func() {
				wg.Done()
			}()
			dec, err := c.Decrypt(nodePrivateKey, value)
			// dec, err := c.Decrypt(nodePrivateKey2, value)
			// dec, err := c.Decrypt(nodePrivateCombinedKey, value)
			if err != nil {
				klog.ErrorS(err, "error when decrypting secret", "name", oldSecret.Name, "key", key, "value", string(value))
				mtx.Lock()
				decErr = append(decErr, fmt.Errorf("error decrypting secret %s, key %s, err %w", oldSecret.Name, key, err).Error())
				mtx.Unlock()
				return
			}
			newSecret.Data[key] = dec
		}(k)
	}
	wg.Wait()

	if len(decErr) > 0 {
		errs := strings.Join(decErr, ", ")
		return nil, errors.New(errs)
	}

	newSecret.Annotations[decryptedKey] = "true"

	klog.InfoS("secret decrypted", "name", newSecret.Name, "elapsed", time.Since(start))

	return newSecret, nil
}

func base64StringToByte(input string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(input)
}
