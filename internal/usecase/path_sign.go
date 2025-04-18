// internal/usecase/path_sign.go
package usecase

import (
    "context"
    "encoding/hex"
    "fmt"

    "github.com/btcsuite/btcd/btcec/v2"
    "github.com/btcsuite/btcd/btcec/v2/schnorr"
    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

func pathSign(b *Backend) *framework.Path {
    return &framework.Path{
        Pattern:        "key-managers/" + framework.GenericNameRegex("name") + "/sign",
        ExistenceCheck: b.pathExistenceCheck,
        Operations: map[logical.Operation]framework.OperationHandler{
            logical.CreateOperation: &framework.PathOperation{Callback: b.signHash},
        },
        HelpSynopsis:    "Sign a 32‑byte hash with secp256k1 (schnorr)",
        HelpDescription: "POST name, hash(hex) → signature(hex).",
        Fields: map[string]*framework.FieldSchema{
            "name": {Type: framework.TypeString},
            "hash": {Type: framework.TypeString},
        },
    }
}

func (b *Backend) signHash(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
    svc := data.Get("name").(string)
    hhex := data.Get("hash").(string)
    km, err := b.retrieveKeyManager(ctx, req, svc)
    if err != nil || km == nil {
        return nil, fmt.Errorf("not found")
    }
    hash, err := hex.DecodeString(hhex)
    if err != nil || len(hash) != 32 {
        return nil, fmt.Errorf("invalid hash")
    }
    privBytes, _ := hex.DecodeString(km.KeyPairs[0].PrivateKey)
    priv, _ := btcec.PrivKeyFromBytes(privBytes)
    sig, err := schnorr.Sign(priv, hash)
    if err != nil {
        return nil, err
    }
    return &logical.Response{Data: map[string]interface{}{
        "signature": hex.EncodeToString(sig.Serialize()),
    }}, nil
}
