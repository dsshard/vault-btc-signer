// internal/usecase/path_read_delete.go

package usecase

import (
    "context"
    "fmt"

    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

func pathReadAndDelete(b *Backend) *framework.Path {
    return &framework.Path{
        Pattern:        "key-managers/" + framework.GenericNameRegex("name"),
        HelpSynopsis:   "Read or delete a key‑manager",
        HelpDescription: `
    GET    key-managers/:name  — возвращает serviceName и список addresses
    DELETE key-managers/:name  — удаляет указанного manager
        `,
        Fields: map[string]*framework.FieldSchema{
            "name": {
                Type:        framework.TypeString,
                Description: "Service name",
            },
        },
        ExistenceCheck: b.pathExistenceCheck,
        Operations: map[logical.Operation]framework.OperationHandler{
            logical.ReadOperation:   &framework.PathOperation{Callback: b.readKeyManager},
            logical.DeleteOperation: &framework.PathOperation{Callback: b.deleteKeyManager},
        },
    }
}

func (b *Backend) readKeyManager(
    ctx context.Context,
    req *logical.Request,
    data *framework.FieldData,
) (*logical.Response, error) {
    serviceName := data.Get("name").(string)
    km, err := b.retrieveKeyManager(ctx, req, serviceName)
    if err != nil {
        return nil, err
    }
    if km == nil {
        return nil, fmt.Errorf("not found")
    }

    addrs := make([]string, len(km.KeyPairs))
    for i, kp := range km.KeyPairs {
        addrs[i] = kp.Address
    }
    return &logical.Response{
        Data: map[string]interface{}{
            "service_name": km.ServiceName,
            "addresses":    addrs,
        },
    }, nil
}

func (b *Backend) deleteKeyManager(
    ctx context.Context,
    req *logical.Request,
    data *framework.FieldData,
) (*logical.Response, error) {
    serviceName := data.Get("name").(string)
    path := fmt.Sprintf("key-managers/%s", serviceName)
    _ = req.Storage.Delete(ctx, path)
    return nil, nil
}
