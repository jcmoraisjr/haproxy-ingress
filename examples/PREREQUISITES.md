# Prerequisites

Many of the examples in this directory have common prerequisites.

## Deploying a controller

You need to deploy HAProxy Ingress controller before running these examples.
You can do so following [these instructions](/examples/deployment).

## Firewall rules

If you're using a generic controller, eg the HAProxy Ingress controller, you
will need to create a firewall rule that targets port 80/443 on the specific VMs
the HAProxy controller is running on. On cloudproviders, the respective backend
will auto-create firewall rules for your Ingress.

## TLS certificates

Unless otherwise mentioned, the TLS secret used in examples is a 2048 bit RSA
key/cert pair with an arbitrarily chosen hostname, created as follows

```console
$ openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout tls.key -out tls.crt -subj "/CN=localhost"
Generating a 2048 bit RSA private key
................+++
................+++
writing new private key to 'tls.key'
-----

$ kubectl create secret tls tls-secret --key tls.key --cert tls.crt
secret "tls-secret" created
```

## CA Authentication
You can act as your very own CA, or use an existing one. As an exercise / learning, we're going to generate our
own CA, and also generate a client certificate.

These instructions are based on CoreOS OpenSSL [instructions](https://coreos.com/kubernetes/docs/latest/openssl.html)

### Generating a CA

First of all, you've to generate a CA. This is going to be the one who will sign your client certificates.
In real production world, you may face CAs with intermediate certificates, as the following:

```console
$ openssl s_client -connect www.google.com:443
[...]
---
Certificate chain
 0 s:/C=US/ST=California/L=Mountain View/O=Google Inc/CN=www.google.com
   i:/C=US/O=Google Inc/CN=Google Internet Authority G2
 1 s:/C=US/O=Google Inc/CN=Google Internet Authority G2
   i:/C=US/O=GeoTrust Inc./CN=GeoTrust Global CA
 2 s:/C=US/O=GeoTrust Inc./CN=GeoTrust Global CA
   i:/C=US/O=Equifax/OU=Equifax Secure Certificate Authority

```

To generate our CA Certificate, we've to run the following commands:

```console
$ openssl genrsa -out ca.key 2048
$ openssl req -x509 -new -nodes -key ca.key -days 10000 -out ca.crt -subj "/CN=example-ca"
```

This will generate two files: A private key (ca.key) and a public key (ca.crt). This CA is valid for 10000 days.
The ca.crt can be used later in the step of creation of CA authentication secret.

### Generating the client certificate

The following steps generate a client certificate signed by the CA generated above. This client can be
used to authenticate in a tls-auth configured ingress.

First, we need to generate an 'openssl.cnf' file that will be used while signing the keys:

```
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
```

Then, a user generates his very own private key (that he needs to keep secret)
and a CSR (Certificate Signing Request) that will be sent to the CA to sign and generate a certificate.

```console
$ openssl genrsa -out client1.key 2048
$ openssl req -new -key client1.key -out client1.csr -subj "/CN=client1" -config openssl.cnf
```

As the CA receives the generated 'client1.csr' file, it signs it and generates a client.crt certificate:

```console
$ openssl x509 -req -in client1.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client1.crt -days 365 -extensions v3_req -extfile openssl.cnf
```

Then, you'll have 3 files: the client.key (user's private key), client.crt (user's public key) and client.csr (disposable CSR).

### Creating the CA Authentication secret

If you're using the CA Authentication feature, you need to generate a secret containing 
all the authorized CAs. You must download them from your CA site in PEM format (like the following):

```
-----BEGIN CERTIFICATE-----
[....]
-----END CERTIFICATE-----
``` 

You can have as many certificates as you want. If they're in the binary DER format, 
you can convert them as the following:

```console
$ openssl x509 -in certificate.der -inform der -out certificate.crt -outform pem
```

Then, you've to concatenate them all in only one file, named 'ca.crt' as the following:


```console
$ cat certificate1.crt certificate2.crt certificate3.crt >> ca.crt
```

The final step is to create a secret with the content of this file. This secret is going to be used in 
the TLS Auth directive:

```console
$ kubectl create secret generic caingress --namespace=default --from-file=ca.crt=<ca.crt>
```

Note: You can also generate the CA Authentication Secret along with the TLS Secret by using:
```console
$ kubectl create secret generic caingress --namespace=default --from-file=ca.crt=<ca.crt> --from-file=tls.crt=<tls.crt> --from-file=tls.key=<tls.key>
```

## Ingress Class

If you have multiple Ingress controllers in a single cluster, you can pick one
by specifying the `ingress.class` annotation, eg creating an Ingress with an
annotation like

```yaml
metadata:
  name: foo
  annotations:
    kubernetes.io/ingress.class: "gce"
```

will target the GCE controller, forcing the HAProxy controller to ignore it, while
an annotation like

```yaml
metadata:
  name: foo
  annotations:
    kubernetes.io/ingress.class: "haproxy"
```

will target the HAProxy controller, forcing the GCE controller to ignore it.

__Note__: Deploying multiple ingress controller and not specifying the
annotation will result in both controllers fighting to satisfy the Ingress.
