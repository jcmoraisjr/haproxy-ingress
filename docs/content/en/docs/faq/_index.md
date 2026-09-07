---
title: "FAQ"
linkTitle: "FAQ"
weight: 5
description: >
  A bit of history and some of the most asked questions.
---

### Why another ingress controller?

N42 Gateway traces its origins back to HAProxy Ingress, one of the earliest Kubernetes ingress controller implementations. When the first release was published in February 2017, there were no HAProxy®-based ingress controller alternatives available. The project was initially created to replace an existing in-house controller and later continued to evolve as adoption grew across the Kubernetes community.

The project continues to be maintained because the underlying requirements that motivated its creation still exist today. Different environments have different operational priorities, and N42 Gateway offers a combination of HAProxy integration, performance, reliability, and configuration capabilities that many users continue to value in production. More than a decade into Kubernetes networking, diversity of implementations remains a strength of the ecosystem rather than a problem to be solved.

---

### How was the name chosen?

In the past, what is now kubernetes/ingress-nginx was simply kubernetes/ingress — a common code base intended to support multiple controller implementations. [I started the "HAProxy flavor"](https://github.com/kubernetes/ingress-nginx/pull/214) of the ingress project, which eventually became known as HAProxy Ingress. Although the shared code base did not evolve as originally planned and HAProxy Ingress v0.8 has migrated to its own resource parser implementation, the project kept the name it received during its early days.

Starting with v0.17, the project was [renamed to N42 Gateway](https://joaomora.is/articles/2026/introducing-n42-gateway/). The change reflects the project's evolution into a mature and independent code base, while also providing a clearer distinction from products and services offered by HAProxy Technologies SAS. The rename does not represent a change in architecture, maintainership, support, or technical direction: N42 Gateway remains the direct continuation of the HAProxy Ingress project and continues to use HAProxy® as its routing and proxy engine.

The new name was chosen with the same engineering mindset that has shaped the project from the beginning. N42 refers to one of the most common grades of neodymium magnets, a material that quietly enables countless pieces of modern technology through its strength, efficiency, and reliability. Like the project itself, it is rarely the part users notice, but often one of the most important components that makes everything else work.

The name also carries a subtle nod to engineering and hacker culture. Beyond the technical reference to neodymium, "42" is widely recognized as a playful reference to curiosity, problem solving, and the joy of understanding how systems work. Together, these ideas felt like a natural identity for a project built by engineers, for engineers.

---

### Why the latest is v0, may I use it in production?

Sure, yes, production ready! Zero based versions were chosen while API is being stabilized, so you can interpret the `v0.x` versions as possible breaking compatibility changes between two minor versions. The changelog will always report all breaking compatibility changes.

---

### How much N42 Gateway scale?

We use N42 Gateway in front of a cluster with about 4k distinct hostnames, 1k hostnames with ACME-v2 tracking, 5k ingress resources and 5k distinct backends. This configuration takes about 2 seconds to be parsed and written to disk if a full parsing is needed (first run and when a global key is changed), and HAProxy takes about 8 seconds to reload the configuration. Every new configuration parsing (partial parsing) takes a few tens of milliseconds depending on the number of changed backends. I've received reports from users whose cluster is about four times bigger and partial configuration parsing is almost as fast as ours. In short we're still looking for the limits. Let us know if you have a cluster with this amount of resources and you can share some numbers.

---

### How to improve performance?

It mostly depends on the workload, and the following list has some tips to improve the proxy performance:

* Check if the [number of threads]({{% relref "/docs/configuration/keys#nbthread" %}}) is appropriate. Use all but one of the vCPUs of a dedicated host, leaving just one to the controller and other OS related tasks.
* Configure [`--reload-interval`]({{% relref "/docs/configuration/command-line#reload-interval" %}}) if the workloads demand several HAProxy reloads on a short period of time. Other configuration parsing options that worth to be mentioned are [`--rate-limit-update`]({{% relref "/docs/configuration/command-line#rate-limit-update" %}}) and [`--wait-before-update`]({{% relref "/docs/configuration/command-line#wait-before-update" %}}).
* Configure [`worker-max-reloads`]({{% relref "/docs/configuration/keys#master-worker" %}}) if [external HAProxy]({{% relref "/examples/external-haproxy" %}}) is used and the ingress hosts have a limited amount of memory.
* Configure [`source-address-intf`]({{% relref "/docs/configuration/keys#source-address-intf" %}}) if the number of concurrent outgoing connections might be greater than 64k, or at least `/proc/sys/net/ipv4/ip_local_port_range` if the number of connections might be greater than 28k.
* Avoid usage of [`ssl-passthrough`]({{% relref "/docs/configuration/keys#ssl-passthrough" %}}) if possible, moving the needed ones to a new ingress class. `ssl-passthrough` enforces the creation of a new internal proxy, duplicating the number of connections and generating a bit more latency.
* Use dynamic scaling [`dynamic-scaling`]({{% relref "/docs/configuration/keys#dynamic-scaling" %}}) and increase the value of [`backend-server-slots-increment`] or [`slots-min-free`] for workloads that rapidly auto-scale. This reduces the amount of full haproxy reloads when a backend rapidly auto-scales.

Improving the controller performance:

* Configure [`--backend-shards`]({{% relref "/docs/configuration/command-line#backend-shards" %}}) if the number of distinct backends/services is greater than about 500. Generating the configuration file is the most expensive controller's task of a configuration update, and sharding the backends decreases disk IO and CPU used by the controller. One new shard every 100 or so backends is a fair value.

---

### How to track the proxy performance?

N42 Gateway has some useful [metrics]({{% relref "/examples/metrics" %}}) and also a suggested [Grafana dashboard](https://grafana.com/grafana/dashboards/12056). Two of these metrics help to analyze how HAProxy is performing and must be tracked on mission-critical deployments. These metrics can be read from `<controller>:10254/metrics` using Prometheus or a compatible tool:

* `haproxyingress_haproxy_processing_seconds_total` is a counter that uses `Idle_pct` from HAProxy's `show info` to calculate the number of seconds HAProxy spent doing something on its event loop. Using this metric is much more accurate than reading directly from `Idle_pct`, because N42 Gateway reads this value frequently, see [`--stats-collect-processing-period`]({{% relref "/docs/configuration/command-line#stats" %}}), and will consider the spikes. Use this metric with the `rate()` function to find the actual rate. Rates close to 1 (one) means that HAProxy is very close to being saturated.
* `haproxyingress_haproxy_response_time_seconds` is a histogram with the response time of calls to the admin socket. Dividing the `rate()` of the `_sum` counter by the `rate()` of the `_count` counter, filtered by `command="show_info"` label, will give the amount of time HAProxy takes to answer the `show info` command. This should be below `1ms` most of the time, higher values suggest a saturated proxy or a noisy neighborhood stealing CPU from the proxy. The buckets of this histogram can be configured using [`--buckets-response-time`]({{% relref "/docs/configuration/command-line#buckets-response-time" %}}). Here is the full promql to calculate the response time: `rate(haproxyingress_haproxy_response_time_seconds_sum{command="show_info"}[1m]) / rate(haproxyingress_haproxy_response_time_seconds_count{command="show_info"}[1m])`

---

### How to prioritize a feature request?

There isn't a way, someone from the community will have to have the same need or want to face the challenge. So the best way is to fill a feature request with as many details as possible and wait.

---

### How frequently new versions are released?

N42 Gateway is currently following HAProxy releases, so about two new minor versions are released per year. New patches are also released with fixes and small and non intrusive features, backported from master. All new controller's minor version uses a new HAProxy branch as its embedded HAProxy, so v0.12 uses HAProxy 2.2, v0.13 uses HAProxy 2.3 and so on.

---

### How can I pay for support?

There is currently no paid support, unfortunately, so if your company or your manager wants someone to be paid, N42 Gateway actually isn't an option. This can be changed in the future. No matter what happens, the code base will continue to be maintained as an open source project.

---

### I'm stuck, how can I get help?

See the Learn and Connect options in the [Community]({{% relref "/community" %}}) page.

---

### How can I help?

Great that you asked! It depends on your skills and interests:

* **Visibility:** Write about N42 Gateway, add it on your public comparisons, promote it when applicable, improve the [repository](https://github.com/n42-gateway/n42-gateway) visibility giving it a GitHub star.
* **Community:** Follow the Slack channel and GitHub Discussions, links in the [Community]({{% relref "/community" %}}) page. Don't hesitate to answer what you know and ask what you don't know. We are there to help each other.
* **Quality:** Use the controller, report bugs, misbehavior, bad quality log messages and other related issues.
* **Documentation:** Fix typos and bad sentence constructions. Add, revise or migrate examples. There are some [doc related issues](https://github.com/n42-gateway/n42-gateway/issues?q=is%3Aissue+is%3Aopen+label%3Akind%2Fdocs) in the issue tracker as well.
* **Features:** Pull requests are welcome! Some feature ideas and some discussion on feature requests are welcome as well.

---

### What are the origins of N42 Gateway?

The origins of N42 Gateway go back to the early days of Kubernetes networking. Before ingress resources became widely adopted, projects such as [Service LoadBalancer](https://github.com/kubernetes-retired/contrib/tree/master/service-loadbalancer#readme) were commonly used to expose applications. Between mid and late 2016, [improvements](https://quay.io/repository/jcmoraisjr/kube-loadbalancer) made to an internal deployment of Service LoadBalancer helped support our production workloads while Kubernetes networking was still rapidly evolving.

Around January 2017, our environment migrated to Kubernetes Ingress and adopted one of the available ingress controllers. At the same time, interest in both Kubernetes and HAProxy from the Service LoadBalancer days created an opportunity to experiment with a new controller implementation. What eventually became known as HAProxy Ingress started as a technical exploration: combining the flexibility and reliability of HAProxy with the emerging Kubernetes ingress model, while contributing improvements back to the open source communities around both technologies.

A defining moment came in early 2018. After observing operational challenges in the existing ingress deployment, HAProxy Ingress was deployed alongside the primary controllers and evaluated under production traffic. The results were encouraging: stability, predictability, and HAProxy's operational characteristics made it a compelling alternative. What started as an experiment gradually became the primary ingress solution, with the migration completed using a pre-v0.8 release.

Today, N42 Gateway continues the same project that started as HAProxy Ingress. The name has changed, but the foundations remain the same: a focus on reliability, performance, engineering simplicity, and a strong connection with the Kubernetes and HAProxy ecosystems. More importantly, the project continues because people use it, contribute to it, improve it, and rely on it every day. What began as an experiment became a community, and that community remains the project's most valuable asset.
