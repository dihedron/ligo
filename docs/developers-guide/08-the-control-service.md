# The control service

Every plugin implements `PluginControl`. It is how `ligo` learns what the plugin is and gives it its instances.

## Describe

`Describe` says what the plugin is. `ligo` calls it when it starts the plugin, and what it answers must not depend on the instances.

```go
func (*plugin) Describe(context.Context, *pluginv1.DescribeRequest) (*pluginv1.DescribeResponse, error) {
    return &pluginv1.DescribeResponse{
        PluginType: "echo.v1", Kind: pluginv1.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER,
        PluginProtocolVersion: 2, PluginVersion: "1.0.0",
        InstanceConfigSchemaJson: configSchema,
        Capabilities: &pluginv1.DescribeResponse_PlatformProvider{PlatformProvider: &pluginv1.PlatformProviderCapabilities{
            AcceptedIdentityModes:  []pluginv1.IdentityMode{pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL},
            ClientOutputSchemaJson: outputSchema,
        }},
    }, nil
}
```

- `PluginProtocolVersion` must be 2. A plugin with another version is refused.
- `InstanceConfigSchemaJson` is a JSON Schema (2020-12) of an instance's `config`. Write it with `"additionalProperties": false`: `ligo` checks every instance against it when the instance is filed, and a field the schema does not know is refused. Embed it with `//go:embed schemas/config.json`.
- The capabilities depend on the kind (see the next chapters). The two output schemas, `ClientOutputSchemaJson`, describe what the plugin puts in a binding for the workload (`spec` or `auth`). `ligo` checks the plugin's output against it.

## The identity mode

An **identity mode** says how the workload will authenticate to the target:

| Mode | The workload |
| :----------------------------------- | :---------------------------------------------- |
| `IDENTITY_MODE_SVID` | Presents its SVID. |
| `IDENTITY_MODE_EXTERNAL_DIR` | Uses an account made in a directory by the identity provider. |
| `IDENTITY_MODE_TARGET_LOCAL` | Uses a user made on the target by the platform provider. |
| `IDENTITY_MODE_DELEGATED_DYNAMIC` | Uses a user the secret store makes on demand. |

An identity provider produces one mode; a platform provider accepts some; a secret store lists, for each of its strategies, the modes it works with. The platform team wires them into a platform, and `ligo` refuses a combination that does not fit.

## ConfigureInstances

`ligo` calls it at start and each time an instance of the plugin's type or realm changes. The request has the **whole** set of instances, and the plugin replaces what it serves.

```go
func (p *plugin) ConfigureInstances(ctx context.Context, r *pluginv1.ConfigureInstancesRequest) (*pluginv1.ConfigureInstancesResponse, error) {
    selectors, out, err := pluginsdk.SelectInstances(ctx, r)
    if err != nil {
        return nil, err
    }
    instances := map[string]*instance{}
    for _, in := range r.GetInstances() {
        c, err := parseConfig([]byte(in.GetConfigJson()), in.GetIdentityMode())
        if err != nil {
            return nil, pluginsdk.Error(codes.InvalidArgument, "INVALID_CONFIG", "instance "+in.GetName()+": "+err.Error(), false)
        }
        instances[in.GetName()] = &instance{config: c, svid: selectors[in.GetName()]}
    }
    p.mu.Lock()
    p.instances = instances // all or nothing
    p.mu.Unlock()
    return out, nil
}
```

- **On an error, keep the previous set.** Build the new map first and swap it in last, as above. `ligo` relies on it: a refused change must not stop the instances that work.
- `pluginsdk.SelectInstances` picks each instance's own SVID among those the SPIRE agent issues to the plugin, with the instance's selector expression, and returns the SPIFFE IDs for the response. The SDK keeps one Workload API client per socket, so calling it on every change leaks nothing.
- Parse the configuration yourself, strictly, and check every rule the schema cannot (a port range, an identifier, that `allowed_endpoints` contains the host). Name the field in the message.
- `ligo` may call the stage services while a `ConfigureInstances` runs: guard the map.

## ValidateInstance

Called when an instance is filed and when it is approved, **before** it serves: *does this instance make sense?*

```go
func (*plugin) ValidateInstance(ctx context.Context, r *pluginv1.ValidateInstanceRequest) (*pluginv1.ValidateInstanceResponse, error) {
    return pluginsdk.ValidateInstance(ctx, r, func(in *pluginv1.InstanceDescriptor) ([]string, error) {
        c, err := parseConfig([]byte(in.GetConfigJson()), in.GetIdentityMode())
        if err != nil {
            return nil, err
        }
        return c.endpoints(), nil // every host:port it would connect to or send a credential to
    })
}
```

It **must not connect** to anything the configuration names: it parses, checks the shape of the bootstrap credential, and selects the SVID. It returns the SPIFFE ID and the endpoints. `ligo` checks the endpoints against the type's `instance_bounds` in `server.yaml`: that is the platform team's limit on where a credential may be sent, and the reason `ValidateInstance` must list **all** of them, the bootstrap Vault included.

## Health

```go
func (p *plugin) Health(ctx context.Context, r *pluginv1.HealthRequest) (*pluginv1.HealthResponse, error) {
    in, err := p.instance(r.GetInstance())
    if err != nil {
        return nil, err
    }
    if err := in.ping(ctx); err != nil {
        return &pluginv1.HealthResponse{Serving: false, PublicMessage: "the target cannot be reached"}, nil
    }
    return &pluginv1.HealthResponse{Serving: true}, nil
}
```

`ligo` calls it before a stage, and the platform list shows its answer. `PublicMessage` is shown to people: fixed text, never the backend's error.

## Errors

Return errors with `pluginsdk.Error(code, ligoCode, publicMessage, retryable)`:

```go
return nil, pluginsdk.Error(codes.Unavailable, "TARGET_UNAVAILABLE", "the target cannot be reached", true)
```

- `ligoCode` is `UPPER_SNAKE_CASE` and stable: the host stores it and operators search for it.
- `publicMessage` is at most 512 characters and holds **no secret, no SQL statement, no backend text**. A database error can echo the statement that failed, which can hold a password; log the SQLSTATE and say something fixed.
- `retryable` tells `ligo` whether to try again with backoff: `true` for a network failure, a timeout, a concurrent change; `false` for a refusal that another try will not change.
- For a resource that belongs to another binding use `pluginsdk.ErrOwnedByOtherBinding`.
