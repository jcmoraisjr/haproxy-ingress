---
title: "Template"
linkTitle: "Template"
weight: 5
description: >
  Overwrite the default template files.
---

Change the default templates mounting a new template file using a ConfigMap.
Note that in the current version, updates to the ConfigMap will not update the
in-memory parsed template.

All templates support [Sprig](https://masterminds.github.io/sprig/) template library. 
This library provides a group of commonly used template functions to work with dictionaries, 
lists, math etc.

> [!NB] Starting from v0.11, all template files were moved from `/etc/haproxy` to `/etc/templates`. Change to an older doc version if using HAProxy Ingress up to v0.10.

Overwriting a template file:

* The links below reference the `master` branch, change to the same tag of your HAProxy Ingress version.
* Change to the `Raw` view
* Copy the whole file and edit it to fit your needs
* Paste the content to a ConfigMap, use the file name as the content key
* Mount the ConfigMap into the Mounting directory (see below) of the HAProxy Ingress pod

> [!WARNING]
>
> Consider overwriting the template files as a last resort. Templates change a lot between HAProxy Ingress versions and the overwrite should be updated on every controller update. Try to use a [configuration snippet]({{% relref "keys/#configuration-snippet" %}}) instead or file a new [feature request](https://github.com/n42-gateway/n42-gateway/issues/new?template=fr.md).

| Mounting directory (v0.11+)  | ConfigMap keys     | Source (v0.11+) | Source (up to v0.10) |
|------------------------------|--------------------|--------|----------------------|
| `/etc/templates/haproxy`     | `haproxy.tmpl`     | [haproxy.tmpl](https://github.com/n42-gateway/n42-gateway/blob/master/rootfs/etc/templates/haproxy/haproxy.tmpl) | [haproxy.tmpl](https://github.com/n42-gateway/n42-gateway/blob/release-0.10/rootfs/etc/haproxy/template/haproxy.tmpl)
| `/etc/templates/modsecurity` | `modsecurity.tmpl` | [modsecurity.tmpl](https://github.com/n42-gateway/n42-gateway/blob/master/rootfs/etc/templates/modsecurity/modsecurity.tmpl) | [spoe-modsecurity.tmpl](https://github.com/n42-gateway/n42-gateway/blob/release-0.10/rootfs/etc/haproxy/modsecurity/spoe-modsecurity.tmpl) |
