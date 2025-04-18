// internal/usecase/backend.go
package usecase

import (
    "context"
    "fmt"

    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

type Backend struct{ *framework.Backend }

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
    b := backend()
    if err := b.Setup(ctx, conf); err != nil {
        return nil, err
    }
    return b, nil
}

func backend() *Backend {
    b := &Backend{}
    b.Backend = &framework.Backend{
        Help: "Vault Bitcoin Signer plugin: key‑managers, sign, build dummy tx",
        Paths: framework.PathAppend(
            paths(b),
        ),
        PathsSpecial: &logical.Paths{
            SealWrapStorage: []string{"key-managers/"},
        },
        BackendType: logical.TypeLogical,
    }
    return b
}

func (b *Backend) pathExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
    entry, err := req.Storage.Get(ctx, req.Path)
    if err != nil {
        b.Logger().Error("existence check failed", "path", req.Path, "err", err)
        return false, fmt.Errorf("existence check failed: %w", err)
    }
    return entry != nil, nil
}
