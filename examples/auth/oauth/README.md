# HAProxy Ingress OAuth2 authentication

This example demonstrates how to configure
[OAuth2](https://oauth.net/2/) on HAProxy Ingress controller.

## Prerequisites

This document has the following prerequisite:

* A Kubernetes cluster with a running HAProxy Ingress controller v0.7 or above.
See the [five minutes deployment](/examples/setup-cluster.md#five-minutes-deployment)
or the [deployment example](/examples/deployment)

## How it works

An OAuth2 configured domain will proxy all of its requests to a local oauth2 proxy.
If the request doesn't provide a cookie with a valid signed token, the browser will
redirect to the OAuth2 provider page, asking the user to login and authorize sending
his email to the application.

If the user authenticate and authorize to share his email address, the provider
will redirect back to the application and the oauth2 proxy will provide a signed
token to the user. If the cookie expires, is removed or its token has an invalid
signature, the OAuth provider will be used again; otherwise, only the local oauth2
proxy is used.

The whole process is transparent to the application, all the access control is
built in the HAProxy configuration.

## Configure an OAuth2 provider

[oauth2-proxy documentation](https://oauth2-proxy.github.io/oauth2-proxy/docs/configuration/oauth_provider/)
has the steps to configure several OAuth2 providers.

## Deploy the proxy

Download and edit
[oauth2-proxy.yaml](https://raw.githubusercontent.com/jcmoraisjr/haproxy-ingress/master/examples/auth/oauth/oauth2-proxy.yaml)
to fit your needs. Change at least the following command-line options:

* `--provider`: See the options on oauth2-proxy [doc](https://oauth2-proxy.github.io/oauth2-proxy/docs/configuration/oauth_provider/).
* `--client-id` and `--client-secret`: ID and secret from the OAuth provider.
* `--cookie-secret`: A base64 encoded 128 bits value.
* `--cookie-secure`: Use true if the application domain uses TLS, use false otherwise. This option is used to choose the protocol in the last redirect.

The cookie secret is used to sign the token sent back to the user's browser.
Use one of the following options to create it - and leave it in a safe place.

On a macOS or Linux terminal:

```
$ dd if=/dev/urandom of=/dev/stdout bs=16 count=1 2>/dev/null|base64
```

Using a python script:

```
$ python -c 'import os,base64; print base64.urlsafe_b64encode(os.urandom(16))'
```

After editing, create the oauth2-proxy deployment and service:

```
$ kubectl create -f oauth2-proxy.yaml
deployment.apps "oauth2-proxy" created
service "oauth2-proxy" exposed
```

## Deploy the application

Create an echoserver deployment. It'll be used to simulate the application
and also check the headers provided by the oauth proxy.

```
$ kubectl run echoserver \
  --image=gcr.io/google_containers/echoserver:1.3 \
  --port=8080 \
  --expose
deployment.apps "echoserver" created
service "echoserver" created
```

Download and edit
[app.yaml](https://raw.githubusercontent.com/jcmoraisjr/haproxy-ingress/master/examples/auth/oauth/app.yaml)
to fit your needs. Change at least the domain on `rules/host` and `tls/hosts`.
Use the same domain configured in the OAuth2 provider and the same URI
prefix configured in the oauth2_proxy deployment.

Internal domains and IPs are supported. Edit `/etc/hosts` or use
[nip.io](http://nip.io) to use a valid domain if you don't have one.

After editing, create the ingress resource:

```
$ kubectl create -f app.yaml
ingress.networking.k8s.io/app created
```

Fire a request to your domain and an optional `/uri`. Your OAuth2
provider will ask you to authenticate. If everything is fine you'll
see `x-auth-request-email` http header with your email account and a
new cookie `_oauth2_proxy` with a signed token. The `/uri` will be
preserved in the last redirect.
