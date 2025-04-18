// internal/usecase/path_transfer_btc.go
package usecase

import (
    "context"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "fmt"

    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

func pathTransferBTC(b *Backend) *framework.Path {
    return &framework.Path{
        Pattern:        "key-managers/" + framework.GenericNameRegex("name") + "/txn/btc/transfer",
        ExistenceCheck: b.pathExistenceCheck,
        Operations: map[logical.Operation]framework.OperationHandler{
            logical.CreateOperation: &framework.PathOperation{Callback: b.transferBTC},
        },
        HelpSynopsis:    "Dummy BTC transfer for tests",
        HelpDescription: "↪ returns base64(privkey) and sha256(privkey).",
        Fields: map[string]*framework.FieldSchema{
            "name": {Type: framework.TypeString},
        },
    }
}

func (b *Backend) transferBTC(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    svc := data.Get("name").(string)
    km, err := b.retrieveKeyManager(ctx, req, svc)
    if err != nil || km == nil {
        return nil, fmt.Errorf("not found")
    }
    priv, _ := hex.DecodeString(km.KeyPairs[0].PrivateKey)
    b64 := base64.StdEncoding.EncodeToString(priv)
    sum := sha256.Sum256(priv)
    return &logical.Response{Data: map[string]interface{}{
        "signed_tx": b64,
        "txid":      hex.EncodeToString(sum[:]),
    }}, nil
}
