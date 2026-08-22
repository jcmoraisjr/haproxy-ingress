---
title: "Migration Guide"
linkTitle: "Migration Guide"
weight: 3
description: >
  Guide for migrating existing HAProxy Ingress deployments to N42 Gateway.
---

N42 Gateway is the continuation of the HAProxy Ingress project. The rename does not introduce architectural changes, compatibility breaks, or changes in project direction, but it does affect component names, image repositories, chart locations, and other deployment artifacts.

This guide describes the available migration paths and the changes operators should be aware of before upgrading existing installations.

## Before you start

Before starting the migration, it is worth understanding what this rename changes - and what it does not. N42 Gateway is the direct continuation of HAProxy Ingress: the routing engine, configuration model, operational behavior and development philosophy remain the same. Most migration tasks are related to project identity - repository names, Helm charts and Kubernetes resource names - rather than application behavior.

**Choose the migration strategy first**: start by deciding whether your environment requires a highly available migration or a short maintenance window is acceptable. The remainder of this guide is organized around these two operational models.

**How long should the migration take**: the migration itself is typically straightforward. In highly available environments, the total duration is usually determined by operational validations and DNS propagation rather than by the controller deployment itself.

**Current stable versions are not impacted**: all new v0.16 and older minor versions still use HAProxy Ingress branding and artifact names. HAProxy Ingress images and chart repository continue in the same URLs. All the Helm charts were migrated to a new location, a HTTP redirect ensures that the new location is found.

**Backward compatible resource configuration**: All the configuration key names remain the same, and the `"haproxy-ingress.github.io/"` annotation prefix is still supported by default. Ingress and Gateway class names are handled during the migration strategies. Metric names are changed and overriding options are also handled during the migration strategies.

Good migration guides minimize surprises. This guide was written with that goal in mind: every externally visible change introduced by the rename is documented below, together with the recommended migration approach.

## Supported versions

This guide describes migration strategies to HAProxy Ingress v0.17 and later. Migration to a newer v0.16 or older minor versions are not impacted by the changes in the branding name.

## Migration strategies

The following migration strategies are supported, choose the one that best suites your use case:

| Strategy                                           | Use case                                                                 | Downtime           | Complexity |
|----------------------------------------------------|--------------------------------------------------------------------------|--------------------|------------|
| [(1) Name override](#strategy-1-name-override)     | Migration preserving component names for production environments         | None or minimal    | Lower      |
| [(2) Side deployment](#strategy-2-side-deployment) | Definitive migration for production environments, depends on (1) applied | None or minimal    | Higher     |
| [(3) Replace](#strategy-3-replace)                 | Delete & reinstall for environments having maintenance window            | Small interruption | Lower      |

### Strategy 1: Name override

Recommended for production environments running v0.16 or older. It consists in configuring the `values.yaml` file so a regular rolling update happens using the same Helm release created for HAProxy Ingress.

#### Overview

The Name override strategy consists in deploying N42 Gateway code using the same HAProxy Ingress resource names, leading to a safe and predictable rolling update process over the same Helm release.

This strategy is a prerequisite before running the definitive migration on [Strategy 2 Side deployment](#strategy-2-side-deployment). Using two distinct strategies allows to separate controller version upgrade from the Helm release migration. It causes none or minimal disruption since it consists in a regular rolling update process.

> [!NB] This is more an upgrade than a migration, so before using this strategy, verify the N42 Gateway release notes in order to understand what changes in the new version.

N42 Gateway `v0.17.0-alpha.3` or newer is required.

> [!NB] N42 Gateway Helm chart has new configuration options supporting the migration, like `chartnameOverride` and `fullControllerName`. These options will continue to be supported indefinitely, fully overriding the branding name even on future N42 Gateway releases.

#### Steps

1. Create and test the `n42-gateway-overrides-values.yaml` file

    Create a new Helm configuration file `n42-gateway-overrides-values.yaml` as a copy of the HAProxy Ingress' one.

    Merge the following content into the `n42-gateway-overrides-values.yaml` file, preserving the old content if already configured:

    ```yaml
    nameOverride: haproxy-ingress ## preserve the same old value if already configured
    fullnameOverride: haproxy-ingress ## preserve the same old value if already configured
    chartnameOverride: haproxy-ingress
    controller:
      ingressClass: haproxy ## preserve the same old value if already configured
      containerName: haproxy-ingress
      initContainerName: haproxy-ingress-init
      fullControllerName: haproxy-ingress.github.io/controller ## add any suffix if using controller.ingressClassResource.controllerClass
      extraArgs:
        configuration-class: n42 ## must match the future ingress/gateway class name on strategy 2
        election-id: class-%s.haproxy-ingress.github.io ## preserve the same old value if already configured
        metrics-namespace: haproxyingress
    ```

    Use `helm template` to ensure that current and new installations render to the same configuration - complete with the parameters you already use on upgrades:

    ```bash
    helm template haproxy-ingress haproxy-ingress/haproxy-ingress \
        ... \
        -f haproxy-ingress-values.yaml | grep -v '^#' >manifests-current.yaml
    helm repo add n42 https://n42-gateway.github.io/charts
    helm template haproxy-ingress n42/n42-gateway \
        --version 0.17.0-alpha.3 --devel ... \
        -f n42-gateway-overrides-values.yaml | grep -v '^#' >manifests-new.yaml
    diff -u manifests-current.yaml manifests-new.yaml
    ```

    Verify if the only changes are the image URL, Helm labels, and the new `--full-controller-name`, `--configuration-class`, `--election-id` and `--metrics-namespace` command-line options.

1. Configure node selector if using DaemonSet

    This step can be fully skipped if using Deployment kind (the default) or node selector is already configured. Configuring node selector allows deploying HAProxy Ingress and N42 Gateway DaemonSets side by side in the same cluster.

    Label all the nodes running HAProxy Ingress - repeat for every node HAProxy Ingress is currently running:

    ```bash
    kubectl label node <node-name> ingress-controller=haproxy-ingress
    ```

    Add the nodeSelector field in both `haproxy-ingress-values.yaml` and `n42-gateway-overrides-values.yaml` files:

    ```yaml
    controller:
      nodeSelector:
        ingress-controller: haproxy-ingress
    ```

    Double check if all the HAProxy Ingress nodes have the configured node selector label:

    ```bash
    kubectl get node -lingress-controller=haproxy-ingress
    ```

1. Update to N42 Gateway

    Start the rolling update using `n42-gateway-overrides-values.yaml`, after confirm the configuration remains the same - complete with the parameters you already use on upgrades:

    ```bash
    helm upgrade haproxy-ingress n42/n42-gateway \
        --version 0.17.0-alpha.3 --devel ... \
        -f n42-gateway-overrides-values.yaml
    ```

1. Validate operation

    Do the usual post-upgrade process you already use to do.

#### Rollback

This strategy describes a regular rolling update process in the same Helm release. In case of problems with the new deployment, rollback the upgrade via `helm rollback` command.

### Strategy 2: Side deployment

Recommended for production environments where service interruption must be avoided. It consists in deploying N42 Gateway side by side with HAProxy Ingress and redirect traffic to the new deployment.

#### Overview

The side deployment strategy consists in deploying N42 Gateway as a new Helm release, along with the HAProxy Ingress one. The traffic is redirected to the new controller in a controlled way.

This is a definitive migration, deploying new components with the new default names, causing none or minimal disruption.

Some of the steps require new command-line options from the v0.17 release for a smooth and secure migration, so the [Strategy 1 Name override](#strategy-1-name-override) is a prerequisite. It is also recommended to migrate to the same N42 Gateway version, fully separating controller upgrade and Helm release migration.

#### Steps

1. Create the `n42-gateway-values.yaml` file

    Create a new Helm configuration file `n42-gateway-values.yaml` as a copy of the HAProxy Ingress' one.

    > Use the regular one as the starting point, without the overrides from the strategy 1

    Only if using DaemonSet kind - update the node selector in the `n42-gateway-values.yaml` file:

    > If node selector is not configured, see the "Configure node selector if using DaemonSet" step in the [Name override strategy](#strategy-1-name-override)

    ```yaml
    controller:
      nodeSelector:
        ingress-controller: n42-gateway
    ```

    Change also the ingressClass field in the `n42-gateway-values.yaml` file if added in the HAProxy Ingress' one, or otherwise it will conflict with the current deployment:

    ```yaml
    controller:
      # this attribute defaults to "n42-gateway", so only needed if already declared
      ingressClass: n42-gateway # ingressClass should match controller.extraArgs.configuration-class from the n42-gateway-overrides-values.yaml file in the strategy 1
    ```

    N42 Gateway uses `n42gateway` as the metrics name prefix. Configure the `n42-gateway-values.yaml` file if you want to preserve backward compatible metrics name:

    ```yaml
    controller:
      extraArgs:
        metrics-namespace: haproxyingress
    ```

1. Deploy N42 Gateway alongside HAProxy Ingress

    Add the N42 Gateway Helm chart repository:

    ```bash
    helm repo add n42 https://n42-gateway.github.io/charts
    ```

    Deploy the new Helm release - complete with the parameters you already use on upgrades:

    ```bash
    helm upgrade n42 n42/n42-gateway \
        --install --namespace n42-gateway-system ... \
        -f n42-gateway-values.yaml
    ```

    Only if using DaemonSet kind - apply the N42 Gateway label on new nodes:

    > Do not `--overwrite`, or otherwise requests directed to HAProxy Ingress should be handled by the new N42 Gateway deployment

    ```bash
    kubectl label node <node-name> ingress-controller=n42-gateway
    ```

    Create a new fronting load balancer for N42 Gateway in case HAProxy Ingress uses one.

1. Check the new deployment

    Check the N42 Gateway pods - they should be healthy, without unexpected errors or warnings on their logs.

    Ingress and Gateway classes, if enabled in Helm configuration, should have one version for HAProxy Ingress, another one for N42 Gateway.

    N42 Ingress and Gateway classes should have the same name configured in HAProxy Ingress' `--configuration-class` command-line option, added via strategy 1.

    A new N42 Gateway service should have the new IP address, if deployed as type LoadBalancer.

1. Redirect traffic

    Update one or a few resources for test:

    > The class name should match the deployed N42 Ingress or Gateway class resource, and also the `--configuration-class` command-line option from the HAProxy Ingress deployment

    ```bash
    kubectl patch ingress <ingress-name> -p '{"spec":{"ingressClassName":"n42-gateway"}}' --type merge
    kubectl patch gateway <gateway-name> -p '{"spec":{"gatewayClassName":"n42-gateway"}}' --type merge
    ```

    Check if the new N42 Gateway controller found the resource, and also the former HAProxy Ingress controller didn't remove it from its configuration.

    > `--configuration-class` in the HAProxy Ingress side ensures that the configuration is still applied, but its IP address is not updated in the resource status

    Check if the Ingress or Gateway resource has its status updated to the new IP address.

    If DNS is manually configured, update the entry for the migrated Ingress/Gateway to, either, the N42 Gateway nodes public address, the N42 Gateway service of type LoadBalancer, or the new fronting load balancer that N42 Gateway uses, depending on your cluster configuration.

1. Test the new deployment

    Test the application after the new DNS address is propagated, or instead configure the new address via `/etc/hosts` file.

    Observe the new application metrics.

    Continue the class name update, always checking its availability and health.

1. Remove legacy deployment

    Check the old controller metrics after finishing all the class updates and after DNS updates are propagated, to ensure that no requests reach it.

    Check the new controller metrics to ensure that everything is going well.

    Remove the old controller:

    ```bash
    helm uninstall haproxy-ingress
    ```

#### Rollback

This strategy describes a manual and step-by-step update of Ingress and Gateway resource class. Revert the Ingress/Gateway class name to the former one in case of any problem, this removes the configuration from the new controller and reverts the status address if configured. Revert also the DNS entry if manually configured.

### Strategy 3: Replace

Recommended for environments where a short maintenance window is acceptable. It consists in removing the Helm release for HAProxy Ingress and installing the N42 Gateway one.

#### Overview

The Replace strategy consists in fully removing the HAProxy Ingress deployment and installing N42 Gateway. As an alternative, both controllers can be deployed side by side in case the environment can serve more than one Ingress/Gateway controller and serve more than one public IP address.

This strategy causes the outage of the applications served by HAProxy Ingress until DNS is fully propagated to the new N42 Gateway deployment.

#### Steps

1. Prepare the environment for N42 Gateway

    Create a new Helm configuration file `n42-gateway-values.yaml` as a copy of the HAProxy Ingress' one.

    N42 Gateway uses `n42gateway` as the metrics name prefix. Configure the `n42-gateway-values.yaml` file if you want to preserve backward compatible metrics name:

    ```yaml
    controller:
      metrics:
        namespace: haproxyingress
    ```

    Add the N42 Gateway Helm chart repository:

    ```bash
    helm repo add n42 https://n42-gateway.github.io/charts
    ```

1. Simpler and faster approach - drop first, install and test later

    Use this approach on environments that cannot deploy and serve more than one Ingress/Gateway controller at the same time, or the rollback operation, in case of a problem, can be slower and cause more outages without further impact.

    Remove HAProxy Ingress:

    ```bash
    helm uninstall haproxy-ingress
    ```

    This approach allows to maintain the same Ingress and Gateway Class names, avoiding to patch the Ingress and Gateway resources. Configure `n42-gateway-values.yaml` accordingly if you want to preserve the name:

    ```yaml
    controller:
      ingressClass: haproxy
    ```

    Install N42 Gateway:
    ```bash
    helm upgrade n42 n42/n42-gateway \
        --install --namespace n42-gateway-system ... \
        -f n42-gateway-values.yaml
    ```

    If DNS is manually configured, update its entry to the IP of new service of type LoadBalancer if one is used to expose the proxy.

1. Safer approach - install and test first, drop later

    Use this approach on environments whose maintenance window should be as short as possible, and supports more than one ingress controller and public IP address at the same time.

    Follow the steps from the [strategy 2 Side deployment](#strategy-2-side-deployment).

    > Note: the difference from the Side deployment strategy and this one is that the Side deployment approach ensures high availability of the applications, while the Replace strategy causes outages due to the configuration being fully removed from HAProxy Ingress before DNS being fully propagated

1. Test the new deployment

    Test the application after the new DNS address is propagated, or instead configure the new address via `/etc/hosts` file.

    Observe the new application metrics.

#### Rollback

This strategy describes a full replacement of HAProxy Ingress to N42 Gateway. If the new deployment does not work as expected:

* If using the simpler approach: remove N42 Gateway Helm release using `helm uninstall n42`, reinstall HAProxy Ingress, and revert the class name of Ingress and Gateway resources in case they were updated.
* If using the safer approach: revert the class name of Ingress and Gateway resources before removing HAProxy Ingress deployment. This moves the configuration back to the HAProxy Ingress controller and reverts the status address if configured.

Revert also the DNS entry if manually configured.

## Need help?

If you encounter issues during migration, please open a GitHub issue or contact us through the community channels.
