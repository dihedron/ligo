# The problem with passwords

Every application talks to other systems: a database, a message broker, an API. Each of those systems asks the same question: **who are you?** Today the answer is almost always a secret that someone created by hand and copied into the application: a password in a configuration file, an API key in a pipeline variable, a certificate passed around by e-mail.

![Today: passwords copied into each application, and remembered by the people who copied them.](why-before.pdf){width=95%}

This works, and it is how most data centres run. But look at what it costs:

- **Nobody knows who can get in.** A password says nothing about who holds it. The same one is often shared by several applications, and remembered by every person who once copied it.
- **It never expires.** Changing a password means finding every copy and changing them together, so it is rarely done. A password leaked five years ago may still work.
- **Taking access away is guesswork.** When an application is retired, its database account usually stays, because nobody is sure what else uses it.
- **Approvals live elsewhere.** The ticket that said "billing may write to the orders database" is in one tool, the account in another, the password in a third. Auditors ask for the link between them, and someone rebuilds it by hand.
- **Every technology is an island.** The cloud has its own identities (AWS IAM roles, GCP service accounts), Kubernetes has others, the data centre has local accounts and LDAP. There is no one place that shows who may reach what across all of them.

The machines already know exactly what they are: an instance in a given OpenStack project, a container on a given LXD server, a pod in a given Kubernetes namespace. What is missing is a way to turn that knowledge into an identity that other systems can verify, and then to turn the identity into access, with the right people's consent.

That is the job of three pieces working together:

1. **SPIFFE**, an open standard for workload identity;
2. **SPIRE** and its attestation plugins, which give every machine and workload a SPIFFE identity, including the companion projects `lxd-spiffe`, `openstack-spiffe` and, soon, `esxi-spiffe`;
3. **`ligo`**, which decides, with the owners' consent, which identities may use which systems, provisions that access and takes it away again.
