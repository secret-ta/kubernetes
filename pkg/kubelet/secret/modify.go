package secret

import (
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

func modify(secret *v1.Secret) *v1.Secret {
	if secret == nil || secret.Annotations == nil {
		return secret
	}
	if _, modified := secret.Annotations["modified"]; modified {
		return secret
	}
	if _, exist := secret.Annotations["testing"]; exist {
		for key, value := range secret.Data {
			newstr := string(value) + ":nekonyan"
			secret.Data[key] = []byte(newstr)
		}
		secret.Annotations["modified"] = "yes"
		klog.InfoS("Modified secret", "name", secret.Name)
	}
	return secret
}
