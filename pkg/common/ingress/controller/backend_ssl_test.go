/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/ingress/store"
	"github.com/jcmoraisjr/haproxy-ingress/pkg/common/task"

	"github.com/stretchr/testify/assert"
	apiv1 "k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/flowcontrol"
)

const (
	// openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout tls.key -out tls.crt -subj "/CN=nginxsvc/O=nginxsvc"
	tlsCrt    = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURIekNDQWdlZ0F3SUJBZ0lKQU1KZld6Mm81cWVnTUEwR0NTcUdTSWIzRFFFQkN3VUFNQ1l4RVRBUEJnTlYKQkFNTUNHNW5hVzU0YzNaak1SRXdEd1lEVlFRS0RBaHVaMmx1ZUhOMll6QWVGdzB4TnpBME1URXdNakF3TlRCYQpGdzB5TnpBME1Ea3dNakF3TlRCYU1DWXhFVEFQQmdOVkJBTU1DRzVuYVc1NGMzWmpNUkV3RHdZRFZRUUtEQWh1CloybHVlSE4yWXpDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTUgzVTYvY3ArODAKU3hJRjltSnlUcGI5RzBodnhsM0JMaGdQWDBTWjZ3d1lISGJXeTh2dmlCZjVwWTdvVHd0b2FPaTN1VFNsL2RtVwpvUi9XNm9GVWM5a2l6NlNXc3p6YWRXL2l2Q21LMmxOZUFVc2gvaXY0aTAvNXlreDJRNXZUT2tVL1dra2JPOW1OCjdSVTF0QW1KT3M0T1BVc3hZZkw2cnJJUzZPYktHS2UvYUVkek9QS2NPMDJ5NUxDeHM0TFhhWDIzU1l6TG1XYVAKYVZBallrN1NRZm1xUm5mYlF4RWlpaDFQWTFRRXgxWWs0RzA0VmtHUitrSVVMaWF0L291ZjQxY0dXRTZHMTF4NQpkV1BHeS9XcGtqRGlaM0UwekdNZnJBVUZibnErN1dhRTJCRzVoUVV3ZG9SQUtWTnMzaVhLRlRkT3hoRll5bnBwCjA3cDJVNS96ZHRrQ0F3RUFBYU5RTUU0d0hRWURWUjBPQkJZRUZCL2U5UnVna0Mwc0VNTTZ6enRCSjI1U1JxalMKTUI4R0ExVWRJd1FZTUJhQUZCL2U5UnVna0Mwc0VNTTZ6enRCSjI1U1JxalNNQXdHQTFVZEV3UUZNQU1CQWY4dwpEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBRys4MXdaSXRuMmFWSlFnejNkNmJvZW1nUXhSSHpaZDhNc1IrdFRvCnpJLy9ac1Nwc2FDR3F0TkdTaHVGKzB3TVZ4NjlpQ3lJTnJJb2J4K29NTHBsQzFQSk9uektSUUdvZEhYNFZaSUwKVlhxSFd2VStjK3ZtT0QxUEt3UjcwRi9rTXk2Yk4xMVI2amhIZ3RPZGdLKzdRczhRMVlUSC9RS2dMd3RJTFRHRwpTZlYxWFlmbnF1TXlZKzFzck00U3ZRSmRzdmFUQmJkZHE2RllpdjhXZFpIaG51ZGlSODdZcFgzOUlTSlFkOXF2CnR6OGthZTVqQVFEUWFiZnFsVWZNT1hmUnhyei96S2NvN3dMeWFMWTh1eVhEWUVIZmlHRWdablV0RjgxVlhDZUIKeU80UERBR0FuVmlXTndFM0NZcGI4RkNGelMyaVVVMDJaQWJRajlvUnYyUWNON1E9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
	tlsKey    = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2Z0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktnd2dnU2tBZ0VBQW9JQkFRREI5MU92M0tmdk5Fc1MKQmZaaWNrNlcvUnRJYjhaZHdTNFlEMTlFbWVzTUdCeDIxc3ZMNzRnWCthV082RThMYUdqb3Q3azBwZjNabHFFZgoxdXFCVkhQWklzK2tsck04Mm5WdjRyd3BpdHBUWGdGTElmNHIrSXRQK2NwTWRrT2IwenBGUDFwSkd6dlpqZTBWCk5iUUppVHJPRGoxTE1XSHkrcTZ5RXVqbXloaW52MmhIY3pqeW5EdE5zdVN3c2JPQzEybDl0MG1NeTVsbWoybFEKSTJKTzBrSDVxa1ozMjBNUklvb2RUMk5VQk1kV0pPQnRPRlpCa2ZwQ0ZDNG1yZjZMbitOWEJsaE9odGRjZVhWagp4c3YxcVpJdzRtZHhOTXhqSDZ3RkJXNTZ2dTFtaE5nUnVZVUZNSGFFUUNsVGJONGx5aFUzVHNZUldNcDZhZE82CmRsT2Y4M2JaQWdNQkFBRUNnZ0VBRGU1WW1XSHN3ZFpzcWQrNXdYcGFRS2Z2SkxXNmRwTmdYeVFEZ0tiWlplWDUKYldPaUFZU3pycDBra2U0SGQxZEphYVdBYk5LYk45eUV1QWUwa2hOaHVxK3dZQzdlc3JreUJCWXgwMzRBamtwTApKMzFLaHhmejBZdXNSdStialg2UFNkZnlBUnd1b1VKN1M3R3V1NXlhbDZBWU1PVmNGcHFBbjVPU0hMbFpLZnNLClN3NXZyM3NKUjNyOENNWVZoUmQ0citGam9lMXlaczJhUHl2bno5c0U3T0ZCSVRGSVBKcE4veG53VUNpWW5vSEMKV2F2TzB5RCtPeTUyN2hBQ1FwaFVMVjRaZXV2bEZwd2ZlWkZveUhnc2YrM1FxeGhpdGtJb3NGakx2Y0xlL2xjZwpSVHNRUnU5OGJNUTdSakJpYU5kaURadjBaWEMvUUMvS054SEw0bXgxTFFLQmdRRHVDY0pUM2JBZmJRY2YvSGh3CjNxRzliNE9QTXpwOTl2ajUzWU1hZHo5Vlk1dm9RR3RGeFlwbTBRVm9MR1lkQ3BHK0lXaDdVVHBMV0JUeGtMSkYKd3EwcEFmRVhmdHB0anhmcyt0OExWVUFtSXJiM2hwUjZDUjJmYjFJWVZRWUJ4dUdzN0hWMmY3NnRZMVAzSEFnNwpGTDJNTnF3ZDd5VmlsVXdSTVptcmJKV3Qwd0tCZ1FEUW1qZlgzc1NWSWZtN1FQaVQvclhSOGJMM1B3V0lNa3NOCldJTVRYeDJmaG0vd0hOL0pNdCtEK2VWbGxjSXhLMmxSYlNTQ1NwU2hzRUVsMHNxWHZUa1FFQnJxN3RFZndRWU0KbGxNbDJQb0ovV2E5c2VYSTAzWWRNeC94Vm5sbzNaUG9MUGg4UmtKekJTWkhnMlB6cCs0VmlnUklBcGdYMXo3TwpMbHg0SEVtaEl3S0JnUURES1RVdVZYL2xCQnJuV3JQVXRuT2RRU1IzNytSeENtQXZYREgxTFBlOEpxTFkxSmdlCjZFc0U2VEtwcWwwK1NrQWJ4b0JIT3QyMGtFNzdqMHJhYnpaUmZNb1NIV3N3a0RWcGtuWDBjTHpiaDNMRGxvOTkKVHFQKzUrSkRHTktIK210a3Y2bStzaFcvU3NTNHdUN3VVWjdtcXB5TEhsdGtiRXVsZlNra3B5NUJDUUtCZ0RmUwpyVk1GZUZINGI1NGV1dWJQNk5Rdi9CYVNOT2JIbnJJSmw3b2RZQTRLcWZYMXBDVnhpY01Gb3MvV2pjc2V0T1puCmNMZTFRYVVyUjZQWmp3R2dUNTd1MEdWQ1Y1QkoxVmFVKzlkTEEwNmRFMXQ4T2VQT1F2TjVkUGplalVyMDBObjIKL3VBeTVTRm1wV0hKMVh1azJ0L0V1WFNUelNQRUpEaUV5NVlRNjl0RkFvR0JBT2tDcW1jVGZGYlpPTjJRK2JqdgpvVmQvSFpLR3YrbEhqcm5maVlhODVxcUszdWJmb0FSNGppR3V3TThqc3hZZW8vb0hQdHJDTkxINndsYlZNTUFGCmlRZG80ZUF3S0xxRHo1MUx4U2hMckwzUUtNQ1FuZVhkT0VjaEdqSW9zRG5Zekd5RTBpSzJGbWNvWHVSQU1QOHgKWDFreUlkazdENDFxSjQ5WlM1OEdBbXlLCi0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K"
	tlsCaName = "ca.crt"
)

func newIngressListenerForBackendSSL(cs *fake.Clientset, ingresses ...*v1beta1.Ingress) store.IngressLister {
	ii := informers.NewSharedInformerFactory(cs, 0).Extensions().V1beta1().Ingresses()
	i := ii.Informer()
	for _, s := range ingresses {
		_ = i.GetStore().Add(s)
	}
	go i.Run(make(chan struct{}))
	return store.IngressLister{
		Lister: ii.Lister(),
	}
}

func buildSecretForBackendSSL(namespace, name string) *apiv1.Secret {
	return &apiv1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
}

func newSecretListerForBackendSSL(cs *fake.Clientset, secrets ...*apiv1.Secret) store.SecretLister {
	si := informers.NewSharedInformerFactory(cs, 0).Core().V1().Secrets()
	i := si.Informer()
	for _, s := range secrets {
		_ = i.GetStore().Add(s)
	}
	go i.Run(make(chan struct{}))
	return store.SecretLister{
		Lister: si.Lister(),
		Client: cs,
	}
}

func newListers(il store.IngressLister, sl store.SecretLister) *ingress.StoreLister {
	return &ingress.StoreLister{
		Ingress: il,
		Secret:  sl,
	}
}

func buildGenericControllerForBackendSSL(cs *fake.Clientset, listers *ingress.StoreLister) *GenericController {
	gc := &GenericController{
		syncRateLimiter: flowcontrol.NewTokenBucketRateLimiter(0.3, 1),
		cfg: &Configuration{
			Client: cs,
		},
		listers:        listers,
		sslCertTracker: newSSLCertTracker(),
	}

	gc.syncQueue = task.NewTaskQueue(gc.syncIngress)
	return gc
}

func buildCrtKeyAndCA() ([]byte, []byte, []byte, error) {
	// prepare
	td, err := ioutil.TempDir("", "ssl")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error occurs while creating temp directory: %v", err)
	}
	ingress.DefaultSSLDirectory = td
	ingress.DefaultCACertsDirectory = td

	dCrt, err := base64.StdEncoding.DecodeString(tlsCrt)
	if err != nil {
		return nil, nil, nil, err
	}

	dKey, err := base64.StdEncoding.DecodeString(tlsKey)
	if err != nil {
		return nil, nil, nil, err
	}

	dCa := dCrt

	return dCrt, dKey, dCa, nil
}

func TestSyncSecret(t *testing.T) {
	// prepare for test
	dCrt, dKey, dCa, err := buildCrtKeyAndCA()
	assert.Nil(t, err, "unexpected error: %v", err)

	cases := map[string]struct {
		secretName    string
		Data          map[string][]byte
		expectSuccess bool
	}{
		"getPemCertificate_error": {"default/foo_secret", map[string][]byte{apiv1.TLSPrivateKeyKey: dKey}, false},
		"normal_test":             {"default/foo_secret", map[string][]byte{apiv1.TLSCertKey: dCrt, apiv1.TLSPrivateKeyKey: dKey, tlsCaName: dCa}, true},
	}

	for n, c := range cases {
		t.Run(n, func(t *testing.T) {
			// init secret for getPemCertificate
			secret := buildSecretForBackendSSL("default", "foo_secret")
			secret.Data = c.Data

			cs := fake.NewSimpleClientset()
			l := newListers(newIngressListenerForBackendSSL(cs), newSecretListerForBackendSSL(cs, secret))
			ic := buildGenericControllerForBackendSSL(cs, l)
			ic.syncSecret(c.secretName)

			_, e := ic.sslCertTracker.Get(c.secretName)
			assert.Equal(t, c.expectSuccess, e)
		})
	}
}

func TestGetPemCertificate(t *testing.T) {
	// prepare
	dCrt, dKey, dCa, err := buildCrtKeyAndCA()
	assert.Nil(t, err)

	cases := map[string]struct {
		secretName string
		data       map[string][]byte
		err        bool
	}{
		"sceret_not_exist":                                  {"default/foo_secret_not_exist", nil, true},
		"data_not_complete_all_not_exist":                   {"default/foo_secret", map[string][]byte{}, true},
		"data_not_complete_TLSCertKey_not_exist":            {"default/foo_secret", map[string][]byte{apiv1.TLSPrivateKeyKey: dKey, tlsCaName: dCa}, false},
		"data_not_complete_TLSCertKeyAndCA_not_exist":       {"default/foo_secret", map[string][]byte{apiv1.TLSPrivateKeyKey: dKey}, true},
		"data_not_complete_TLSPrivateKeyKey_not_exist":      {"default/foo_secret", map[string][]byte{apiv1.TLSCertKey: dCrt, tlsCaName: dCa}, false},
		"data_not_complete_TLSPrivateKeyKeyAndCA_not_exist": {"default/foo_secret", map[string][]byte{apiv1.TLSCertKey: dCrt}, true},
		"data_not_complete_CA_not_exist":                    {"default/foo_secret", map[string][]byte{apiv1.TLSCertKey: dCrt, apiv1.TLSPrivateKeyKey: dKey}, false},
		"normal_test":                                       {"default/foo_secret", map[string][]byte{apiv1.TLSCertKey: dCrt, apiv1.TLSPrivateKeyKey: dKey, tlsCaName: dCa}, false},
	}

	for n, c := range cases {
		t.Run(n, func(t *testing.T) {
			cs := fake.NewSimpleClientset()
			l := newListers(newIngressListenerForBackendSSL(cs), newSecretListerForBackendSSL(cs))
			ic := buildGenericControllerForBackendSSL(cs, l)
			secret := buildSecretForBackendSSL("default", "foo_secret")
			secret.Data = c.data
			_, _ = ic.listers.Secret.Client.CoreV1().Secrets(secret.Namespace).Create(secret)
			sslCert, err := ic.getPemCertificate(secret)

			if c.err {
				assert.NotNil(t, err, "expected error")
				return
			}
			assert.Nil(t, err, "unexpected error: %v", err)
			assert.NotNil(t, sslCert, "ingress.SSLCert expected, got nil")
		})
	}
}
