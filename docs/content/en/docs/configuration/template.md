---
title: "Template"
linkTitle: "Template"
weight: 1
description: >
  Overwrite the default template files.
---

Change the default templates mounting a new template file using a configmap.
Note that in the current version, updates to the configmap will not update the
in-memory parsed template.

All templates support [Sprig](https://masterminds.github.io/sprig/) template library. 
This library provides a group of commonly used template functions to work with dictionaries, 
lists, math etc.

| Mounting directory         | Configmap keys (filenames) | Source (choose a proper tag)                                                   |
|----------------------------|----------------------------|--------------------------------------------------------------------------------|
| `/etc/haproxy/template`    | `haproxy.tmpl`             | [haproxy.tmpl](https://github.com/jcmoraisjr/haproxy-ingress/blob/release-0.8/rootfs/etc/haproxy/template/haproxy.tmpl)                      |
| `/etc/haproxy/modsecurity` | `spoe-modsecurity.tmpl`    | [spoe-modsecurity.tmpl](https://github.com/jcmoraisjr/haproxy-ingress/blob/release-0.8/rootfs/etc/haproxy/modsecurity/spoe-modsecurity.tmpl) |
