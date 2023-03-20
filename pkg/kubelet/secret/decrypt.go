package secret

import (
	"fmt"
	"sync"

	cryptomodule "github.com/secret-ta/k8s-ta-internal-crypto-library"
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

const (
	keyFile          = "/var/lib/kubelet/pki/secrets.key"
	encryptedKey     = "encrypted"
	shouldDecryptKey = "should-decrypt"
)

var (
	privatekey []byte
	c          = cryptomodule.NewCryptoModule(nil)
)

func init() {
	p, err := c.KeyFromFile(keyFile)
	if err != nil {
		klog.ErrorS(err, "error reading secrets private key")
		// panic(err.Error())
	}
	klog.Info("private key for secrets ok")
	privatekey = p
}

func decrypt(secret *v1.Secret) *v1.Secret {
	// secret is nil then return
	if secret == nil {
		return secret
	}

	// deep copy secret
	newsecret := secret.DeepCopy()

	// annotations are nil, replace with new one
	if newsecret.Annotations == nil {
		newsecret.Annotations = map[string]string{}
	}

	// check if secret should be decrypted, if not ignore
	if _, encrypted := newsecret.Annotations[encryptedKey]; !encrypted {
		return secret
	}
	if _, shouldDecrypt := newsecret.Annotations[shouldDecryptKey]; !shouldDecrypt {
		return secret
	}

	// privatekey is nil, ignoring
	if privatekey == nil || (privatekey != nil && len(privatekey) == 0) {
		klog.ErrorS(nil, "unable to proceed decrypting secret due to nil private key", "name", newsecret.Name)
		return secret
	}

	klog.InfoS("decrypting secret", "name", newsecret.Name)

	var (
		wg     sync.WaitGroup
		decErr []error
		mtx    sync.Mutex
	)
	wg.Add(len(newsecret.Data))
	for k, v := range newsecret.Data {
		go func(key string, value []byte) {
			defer func() {
				wg.Done()
			}()
			dec, err := c.Decrypt(privatekey, value)
			if err != nil {
				klog.ErrorS(err, "error when decrypting secret", "name", secret.Name, "key", key)
				mtx.Lock()
				decErr = append(decErr, fmt.Errorf("error decrypting secret %s key %s err %w", secret.Name, key, err))
				mtx.Unlock()
				return
			}
			newsecret.Data[key] = dec
		}(k, v)
	}
	wg.Wait()

	// - if there's any error, return old secret
	if len(decErr) > 0 {
		return secret
	}

	return newsecret
}
