package secret

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	cryptomodule "github.com/secret-ta/k8s-ta-internal-crypto-library"
	v1 "k8s.io/api/core/v1"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
)

const (
	secretKey = "/var/lib/kubelet/pki/secrets.key"

	interceptorKey = "/var/lib/kubelet/pki/interceptor-publickey.pem"

	encryptedKey     = "encrypted"
	shouldDecryptKey = "should-decrypt"
	decryptedKey     = "decrypted"
	verifiedKey      = "verified"

	signedKey    = "signed"
	signatureKey = "signature"

	verifyErrorEventFormat  = "Failed verifying secret '%s' in namespace '%s' due to error %w"
	decryptErrorEventFormat = "Failed decrypting secret '%s' in namespace '%s' due to error %w"

	decryptEvent = "Decrypt"
	verifyEvent  = "Verify"
)

var (
	// - node private key
	nodePrivateKey []byte

	// - interceptor public key
	interceptorPublicKey []byte

	c = cryptomodule.NewCryptoModule(nil)
)

type (
	decryptor struct {
		clientset k8s.Interface
		recorder  record.EventRecorder
	}
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

func newDecryptor(kubeClient k8s.Interface, recorder record.EventRecorder) *decryptor {
	return &decryptor{kubeClient, recorder}
}

func (d *decryptor) process(secret *v1.Secret) (*v1.Secret, error) {
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
	newSecret, err := d.decrypt(secret, newSecret)
	if err != nil {
		return nil, err
	}

	// - check hash
	secretOk, err := d.verify(newSecret)
	if err != nil {
		return nil, fmt.Errorf("failed verifying secret due to error, error %w", err)
	}

	// - secret's signature is invalid, return empty secret
	if !secretOk {
		return nil, fmt.Errorf("integrity check for secret %s failed", newSecret.Name)
	}

	return newSecret, nil
}

func (d *decryptor) verify(secret *v1.Secret) (bool, error) {
	if vRes, verified := secret.Annotations[verifiedKey]; verified {
		d.recorder.Eventf(secret, v1.EventTypeNormal, verifyEvent, "Secret '%s' in namespace '%s' already verified with result %s", secret.Name, secret.Namespace, vRes)
		klog.InfoS("secret already verified", "name", secret.Name)

		res, _ := strconv.ParseBool(vRes)
		return res, nil
	}
	// check if secret's signature should be checked, if not ignore
	if sign, signed := secret.Annotations[signedKey]; !signed || sign != "true" {
		return true, nil
	}

	d.recorder.Eventf(secret, v1.EventTypeNormal, verifyEvent, "Verifying secret '%s' in namespace '%s'", secret.Name, secret.Namespace)
	klog.InfoS("verifying secret", "name", secret.Name)
	start := time.Now()

	signature, exist := secret.Annotations[signatureKey]
	if !exist {
		err := errors.New("signature doesn't exist")
		d.recorder.Eventf(secret, v1.EventTypeWarning, verifyEvent, verifyErrorEventFormat, secret.Name, secret.Namespace, err)
		klog.ErrorS(nil, "secret's signature doesn't exist", "name", secret.Name)
		return false, err
	}

	dataByte, err := json.Marshal(secret.Data)
	if err != nil {
		d.recorder.Eventf(secret, v1.EventTypeWarning, verifyEvent, verifyErrorEventFormat, secret.Name, secret.Namespace, err)
		klog.ErrorS(err, "failed marshaling secret", "name", secret.Name)
		return false, fmt.Errorf("failed marshaling secret, error %w", err)
	}

	signatureByte, err := base64StringToByte(signature)
	if err != nil {
		err = fmt.Errorf("malformed signature, error %w", err)
		d.recorder.Eventf(secret, v1.EventTypeWarning, verifyEvent, verifyErrorEventFormat, secret.Name, secret.Namespace, err)
		klog.ErrorS(err, "malformed signature", "name", secret.Name)
		return false, err
	}

	ok := c.Verify(interceptorPublicKey, dataByte, signatureByte)

	secret.Annotations[verifiedKey] = strconv.FormatBool(ok)

	elapsed := time.Since(start)
	d.recorder.Eventf(secret, v1.EventTypeNormal, verifyEvent, "Verifying secret '%s' in namespace '%s' done with result %v (elapsed %v)", secret.Name, secret.Namespace, ok, elapsed)
	klog.InfoS("verifying secret done", "name", secret.Name, "elapsed", elapsed)

	return ok, nil
}

func (d *decryptor) decrypt(oldSecret, newSecret *v1.Secret) (*v1.Secret, error) {
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
		err := errors.New("malformed private key")
		d.recorder.Eventf(oldSecret, v1.EventTypeWarning, decryptEvent, decryptErrorEventFormat, oldSecret.Name, oldSecret.Namespace, err)
		klog.ErrorS(nil, "unable to proceed decrypting secret due to nil private key", "name", newSecret.Name)
		return nil, err
	}

	d.recorder.Eventf(oldSecret, v1.EventTypeNormal, decryptEvent, "Decrypting secret '%s' in namespace '%s'", oldSecret.Name, oldSecret.Namespace)
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
				d.recorder.Eventf(oldSecret, v1.EventTypeWarning, decryptEvent, decryptErrorEventFormat, oldSecret.Name, oldSecret.Namespace, err)
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

	elapsed := time.Since(start)
	d.recorder.Eventf(oldSecret, v1.EventTypeNormal, decryptEvent, "Decrypting secret '%s' in namespace '%s' done (elapsed %v)", oldSecret.Name, oldSecret.Namespace, elapsed)
	klog.InfoS("secret decrypted", "name", newSecret.Name, "elapsed", elapsed)

	return newSecret, nil
}

func base64StringToByte(input string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(input)
}
