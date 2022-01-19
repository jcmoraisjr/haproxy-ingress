---
title: "FAQ"
linkTitle: "FAQ"
weight: 5
description: >
  A bit of history and some of the most asked questions.
---

### Why another ingress controller?

HAProxy Ingress is one of the first ingress controller implementations, there wasn't any HAProxy based one when v0.1 was released on feb/2017. It was maintained since then because it replaced our former controller at work, and also and not less important because it was being used by a growing number of users.

---

### How was the name chosen?

In the past, what is now kubernetes/ingress-nginx was just kubernetes/ingress - a common code base that could be used by controller developers. [I started the "HAProxy flavor"](https://github.com/kubernetes/ingress-nginx/pull/214) of the ingress project, leading to HAProxy Ingress as the name. The common code base didn't evolve as it was initially planned, and since v0.8 HAProxy Ingress has its own resource parser implementation - but without changing the name received on its debut.

---

### Why the latest is v0, may I use it in production?

Sure, yes, production ready! Zero based versions were chosen while API is being stabilized, so you can interpret the `v0.x` versions as possible breaking compatibility changes between two minor versions. The changelog will always report all breaking compatibility changes.

---

### How many active users HAProxy Ingress have?

I don't know, both HAProxy (the load balancer) and HAProxy Ingress don't advertise themselves and don't track users. It should be between several hundreds and a few thousands based on the number of downloads (specially from Quay), the number of users in the Slack channel (started nov/2020) and how fast issues from some very specific scenarios used to be reported.

---

### How much HAProxy Ingress scale?

We use HAProxy Ingress in front of a cluster with about 4k distinct hostnames, 1k hostnames with ACME-v2 tracking, 5k ingress resources and 5k distinct backends. This configuration takes about 2 seconds to be parsed and written to disk if a full parsing is needed (first run and when a global key is changed), and HAProxy takes about 8 seconds to reload the configuration. Every new configuration parsing (partial parsing) takes a few tens of milliseconds depending on the number of changed backends. I've received reports from users whose cluster is about four times bigger and partial configuration parsing is almost as fast as ours. In short we're still looking for the limits. Let us know if you have a cluster with this amount of resources and you can share some numbers.

---

### How to improve performance?

It mostly depends on the workload, and the following list has some tips to improve the proxy performance:

* Check if the [number of threads]({{% relref "/docs/configuration/keys#nbthread" %}}) is appropriate. Use all but one of the vCPUs of a dedicated host, leaving just one to the controller and other OS related tasks.
* Configure [`--reload-interval`]({{% relref "/docs/configuration/command-line#reload-interval" %}}) if the workloads demand several HAProxy reloads on a short period of time. Other configuration parsing options that worth to be mentioned are [`--rate-limit-update`]({{% relref "/docs/configuration/command-line#rate-limit-update" %}}) and [`--wait-before-update`]({{% relref "/docs/configuration/command-line#wait-before-update" %}}).
* Configure [`worker-max-reloads`]({{% relref "/docs/configuration/keys#master-worker" %}}) if [external HAProxy]({{% relref "/docs/examples/external-haproxy" %}}) is used and the ingress hosts have a limited amount of memory.
* Configure [`source-address-intf`]({{% relref "/docs/configuration/keys#source-address-intf" %}}) if the number of concurrent outgoing connections might be greater than 64k, or at least `/proc/sys/net/ipv4/ip_local_port_range` if the number of connections might be greater than 28k.
* Avoid usage of [`ssl-passthrough`]({{% relref "/docs/configuration/keys#ssl-passthrough" %}}) if possible, moving the needed ones to a new ingress class. `ssl-passthrough` enforces the creation of a new internal proxy, duplicating the number of connections and generating a bit more latency.
* Use dynamic scaling [`dynamic-scaling`]({{% relref "/docs/configuration/keys/#dynamic-scaling" %}}) and increase the value of [`backend-server-slots-increment`] for workloads that auto-scale. This reduces the amount of full haproxy reloads every time a backend auto-scales.

Improving the controller performance:

* Configure [`--backend-shards`]({{% relref "/docs/configuration/command-line#backend-shards" %}}) if the number of distinct backends/services is greater than about 500. Generating the configuration file is the most expensive controller's task of a configuration update, and sharding the backends decreases disk IO and CPU used by the controller. One new shard every 100 or so backends is a fair value.

---

### How to track the proxy performance?

HAProxy Ingress has some useful [metrics]({{% relref "/docs/examples/metrics" %}}) and also a suggested [Grafana dashboard](https://grafana.com/grafana/dashboards/12056). Two of these metrics help to analyze how HAProxy is performing and must be tracked on mission-critical deployments. These metrics can be read from `<controller>:10254/metrics` using Prometheus or a compatible tool:

* `haproxyingress_haproxy_processing_seconds_total` is a counter that uses `Idle_pct` from HAProxy's `show info` to calculate the number of seconds HAProxy spent doing something on its event loop. Using this metric is much more accurate than reading directly from `Idle_pct`, because HAProxy Ingress reads this value frequently, see [`--stats-collect-processing-period`]({{% relref "/docs/configuration/command-line#stats" %}}), and will consider the spikes. Use this metric with the `rate()` function to find the actual rate. Rates close to 1 (one) means that HAProxy is very close to being saturated.
* `haproxyingress_haproxy_response_time_seconds` is a histogram with the response time of calls to the admin socket. Dividing the `rate()` of the `_sum` counter by the `rate()` of the `_count` counter, filtered by `command="show_info"` label, will give the amount of time HAProxy takes to answer the `show info` command. This should be below `1ms` most of the time, higher values suggest a saturated proxy or a noisy neighborhood stealing CPU from the proxy. The buckets of this histogram can be configured using [`--buckets-response-time`]({{% relref "/docs/configuration/command-line#buckets-response-time" %}}). Here is the full promql to calculate the response time: `rate(haproxyingress_haproxy_response_time_seconds_sum{command="show_info"}[1m]) / rate(haproxyingress_haproxy_response_time_seconds_count{command="show_info"}[1m])`

---

### How to prioritize a feature request?

There isn't a way, someone from the community will have to have the same need or want to face the challenge. So the best way is to fill a feature request with as many details as possible and wait.

---

### How frequently new versions are released?

HAProxy Ingress is currently following HAProxy releases, so about two new minor versions are released per year. New patches are also released with fixes and small and non intrusive features, cherry-picked from master. All new controller's minor version uses a new HAProxy branch as its embedded HAProxy, so v0.12 uses HAProxy 2.2, v0.13 uses HAProxy 2.3 and so on.

---

### How can I pay for support?

There is currently no paid support, unfortunately, so if your company or your manager wants someone to be paid, HAProxy Ingress actually isn't an option. This can be changed in the future. No matter what happens, the code base will continue to be maintained as an open source project.

---

### I'm stuck, how can I get help?

See the Learn and Connect options in the [Community]({{% relref "/community" %}}) page.

---

### How can I help?

Great that you asked! It depends on your skills and interests:

* **Visibility:** Write about HAProxy Ingress, add it on your public comparisons, promote it when applicable, improve the [repository](https://github.com/jcmoraisjr/haproxy-ingress) visibility giving it a GitHub star.
* **Community:** Follow the Slack channel, mailing list, and Stack Overflow tag, links in the [Community]({{% relref "/community" %}}) page. Don't hesitate to answer what you know and ask what you don't know. We are there to help each other.
* **Quality:** Use the controller, report bugs, misbehavior, bad quality log messages and other related issues.
* **Documentation:** Fix typos and bad sentence constructions. Add, revise or migrate examples. There are some [doc related issues](https://github.com/jcmoraisjr/haproxy-ingress/issues?q=is%3Aissue+is%3Aopen+label%3Akind%2Fdocs) in the issue tracker as well.
* **Features:** Pull requests are welcome! Some feature ideas and some discussion on feature requests are welcome as well.

---

### Why did you start and still implement HAProxy Ingress?

[Service loadbalancer](https://github.com/kubernetes-retired/contrib/tree/master/service-loadbalancer#readme) was a kind of pre-ingress component that I've [improved](https://quay.io/repository/jcmoraisjr/kube-loadbalancer), between jul and dec/2016, to meet our needs at work. About jan/2017 we migrated to ingress and deployed a controller. I was enjoying to play with Kubernetes, as much as with HAProxy in the service-loadbalancer days, so I chose to start the controller just to see how far I could go. HAProxy Ingress was conceived because, in one single project, I could use two technologies that I love - HAProxy and Kubernetes, and also to improve two other skills - writing infrastructure code and contributing back to the great communities around HAProxy and Kubernetes.

Early 2018 we observed some annoying issues in the controller we were using, probably due to the amount of configuration updates that enforces the reload of the proxy. At the same time my manager and I observed how stable a HAProxy deployment is, after deploying a HAProxy Ingress instance side by side with the former controllers, but outside the DNS. "Hey Joao, what if we move some requests to HAProxy and see how it behaves?". This sentence started our move to HAProxy Ingress, which was completed with a v0.8-snapshot version.

HAProxy Ingress is still on the road mainly due to the following reasons, with no special order: it's being used and useful, it's developed with passion, and we built a great community around it. These last years were awesome, looking forward to the years to come.
