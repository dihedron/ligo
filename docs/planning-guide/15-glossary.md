# Glossary

| Term | Meaning |
| :-------------------- | :------------------------------------------------------------ |
| Access level | A named set of privileges a target offers, within its platform's bounds |
| Account | A registered tenant: a root jurisdiction, its people in the directory, its workloads under its own SPIFFE paths |
| Additional party | A jurisdiction whose approvers must also consent to a binding, as the interconnection policy names it |
| Binding | The link that lets one source use one target at one access level |
| Break-glass | An emergency change, applied at once by a person on call; a create or update is reverted unless ratified |
| Bundle | The certificates and keys that verify a trust domain's SVIDs |
| Change request | A proposed change to a source, target or binding, decided side by side |
| Charter | The set of rules every jurisdiction must comply with: how jurisdictions are derived, their name prefixes, which may bind to which, and accounts; one per installation |
| Core realm | The realm `ligo`'s own identity comes from |
| Federation | A SPIRE server keeping another trust domain's bundle, so that its workloads can be verified without an agent of that domain |
| Installation | One `ligo` database, and the replicas that share it |
| Interconnection policy | The charter's ordered rules on which pairs of jurisdictions may bind |
| Jurisdiction | Who decides about a source, a target, a platform or one side of a change; a path such as `dc/prod/data/orders` |
| Network zone | A network segment with its own security level and reachability: a data centre segment, a DMZ, a cloud region |
| Platform | A system that hosts targets, configured by the platform team, such as a PostgreSQL server |
| Platform approver | An approver of a shared platform's jurisdiction, who may decide a binding's target side |
| Realm | One trust domain, its SPIRE agent socket on the `ligo` host, and the plugin processes attached to it |
| Registrar | Whoever creates SPIRE entries for workloads, and so assigns their SPIFFE paths |
| Replica | One `ligo serve` process; all replicas of an installation are equal |
| Side | The part of a change one jurisdiction decides: source, target, owner, platform or an additional party |
| Source | A group of client workloads, defined by a SPIFFE ID regex in one trust domain |
| SVID | A SPIFFE identity document: an X.509 certificate or a JWT |
| Target | One resource on a platform, such as a schema, with its access levels |
| Tenancy | A target on a shared platform belonging to one account: on PostgreSQL, one schema |
| Transit key | The Vault or OpenBao key that seals secrets between pipeline stages |
| Trust domain | The namespace of SPIFFE IDs one SPIRE server signs for |
| Trusted automation | A SPIFFE identity that decides sides of its own jurisdictions by delegation, citing an upstream approval |
