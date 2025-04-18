// internal/usecase/key_managers.go
package usecase

import (
    "context"
    "fmt"

    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

type KeyPair struct {
    PrivateKey string `json:"private_key"`
    PublicKey  string `json:"public_key"`
    Address    string `json:"address"`
}

type KeyManager struct {
    ServiceName string     `json:"service_name"`
    KeyPairs    []*KeyPair `json:"key_pairs"`
}

func paths(b *Backend) []*framework.Path {
    return []*framework.Path{
        pathCreateAndList(b),
        pathReadAndDelete(b),
        pathSign(b),
        pathTransferBTC(b),
    }
}

func (b *Backend) retrieveKeyManager(ctx context.Context, req *logical.Request, svc string) (*KeyManager, error) {
    path := fmt.Sprintf("key-managers/%s", svc)
    entry, err := req.Storage.Get(ctx, path)
    if err != nil {
        return nil, err
    }
    if entry == nil {
        return nil, nil
    }
    var km KeyManager
    if err := entry.DecodeJSON(&km); err != nil {
        return nil, err
    }
    return &km, nil
}
