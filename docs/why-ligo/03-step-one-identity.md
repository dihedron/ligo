# Step one: an identity for every workload

Before any access can be granted to a workload, the workload must be able to prove who it is. SPIRE does this, platform by platform, through node attestor plugins: each one knows how to ask a platform "is this machine really what it claims to be?".

![Step one: each platform vouches for its machines through a node attestor, and SPIRE turns that into SVIDs.](why-identity.pdf){width=100%}

## The public clouds and Kubernetes

SPIRE ships attestors for the platforms that already sign an identity for their machines: `aws_iid` checks the instance identity document signed by AWS, `gcp_iit` the identity token signed by Google, `azure_msi` the managed identity token of Azure, and `k8s_psat` the projected service account token of Kubernetes. On these platforms, giving workloads an identity is a matter of installing SPIRE.

## The private cloud and the data centre: the companion projects

LXD, OpenStack and ESXi sign nothing of the kind. The companion projects fill that gap, each with the same rule: **trust only what the platform says, never what the machine says about itself**.

- **`lxd-spiffe`** attests LXD containers and virtual machines. The SPIRE Server finds the instance through the LXD API, then challenges it with a proof that only that instance can answer: a file the server reads back from inside it, or a one-time value the server writes into its configuration. Its selectors (project, profiles, networks, type) come from the LXD API only.
- **`openstack-spiffe`** attests OpenStack instances. Its issuer hands each instance, through Nova's vendor data, a short-lived token that it signs only after checking the instance with Keystone and the Nova API. SPIRE verifies the token against the issuer's published keys, and builds the identity from the instance's project and instance ID.
- **`esxi-spiffe`**, planned, will do the same for virtual machines on VMware ESXi, which still host much of the traditional data centre.

With these, the same kind of identity is available everywhere a workload can run: a container on a developer's LXD server, an instance in the private cloud, a virtual machine in the data centre, an EC2 instance or a GKE pod. Every one of them gets a SPIFFE ID and short-lived SVIDs, renewed automatically, without a single password.

## What identity alone does not give

An identity answers "who are you?". It does not answer the next questions:

- What may this workload use, and at which level?
- Who agreed to that, and when?
- How does a database that knows nothing about SPIFFE let it in?
- How is the access taken away when the workload is retired or compromised?

Those are step two.
