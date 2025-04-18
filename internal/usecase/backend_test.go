// internal/usecase/backend_test.go
package usecase

import (
    "context"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "testing"

    "github.com/btcsuite/btcd/btcec/v2/schnorr"
    "github.com/hashicorp/vault/sdk/logical"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func newTestBackend(t *testing.T) (*Backend, logical.Storage) {
    t.Helper()
    storage := &logical.InmemStorage{}
    b, err := Factory(context.Background(), &logical.BackendConfig{
        StorageView: storage,
    })
    if err != nil {
        t.Fatalf("Factory error: %v", err)
    }
    be, ok := b.(*Backend)
    if !ok {
        t.Fatalf("unexpected backend type: %T", b)
    }
    return be, storage
}


func TestCreateAndListKeyManagers(t *testing.T) {
    b, storage := newTestBackend(t)
    // Import specific privkey
    req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
    req.Storage = storage
    // 32‑byte secp256k1 privkey hex
    req.Data = map[string]interface{}{
        "serviceName": "svc",
        "privateKey":  "KzQJ9vR4JeoJicejXmdvjcoDmZHa665diNxt17o3KRw3Hvix5CA5",
    }
    resp, err := b.HandleRequest(context.Background(), req)
    require.NoError(t, err)
    addr := resp.Data["address"].(string)
    assert.Equal(t, "bc1qyr5sfdeg3570txvn7adftehdqz74fm7t8flp03k8d6xwhf8kkd9xd4y073", addr)

    // Generate another key
    req = logical.TestRequest(t, logical.UpdateOperation, "key-managers")
    req.Storage = storage
    req.Data = map[string]interface{}{"serviceName": "svc"}
    _, err = b.HandleRequest(context.Background(), req)
    require.NoError(t, err)

    // List
    req = logical.TestRequest(t, logical.ListOperation, "key-managers")
    req.Storage = storage
    resp, err = b.HandleRequest(context.Background(), req)
    require.NoError(t, err)
    assert.Equal(t, []string{"svc"}, resp.Data["keys"].([]string))

    // Read
    req = logical.TestRequest(t, logical.ReadOperation, "key-managers/svc")
    req.Storage = storage
    resp, err = b.HandleRequest(context.Background(), req)
    require.NoError(t, err)
    addrs := resp.Data["addresses"].([]string)
    assert.Len(t, addrs, 2)
}


func TestCreateAndListKeyManagers2(t *testing.T) {
    b, storage := newTestBackend(t)
    // Import specific privkey
    req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
    req.Storage = storage
    // 32‑byte secp256k1 privkey hex
    req.Data = map[string]interface{}{
        "serviceName": "svc",
        "privateKey":  "",
    }
    resp, err := b.HandleRequest(context.Background(), req)
    require.NoError(t, err)
    addr := resp.Data["address"].(string)
    // bitcoin mainnet taproot address regexp
    assert.Regexp(t, `^bc1[a-z0-9]{39,}$`, addr)
}


func TestCreateAndListKeyManagers3(t *testing.T) {
    b, storage := newTestBackend(t)
    // Import specific privkey
    req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
    req.Storage = storage
    // 32‑byte secp256k1 privkey hex
    req.Data = map[string]interface{}{
        "serviceName": "svc",
        "privateKey":  "123",
    }

    _, err := b.HandleRequest(context.Background(), req)
    require.Error(t, err)
    assert.Contains(t, err.Error(), "invalid private key")
}

func TestSignHash(t *testing.T) {
    b, storage := newTestBackend(t)
    // create
    req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
    req.Storage = storage
    req.Data = map[string]interface{}{"serviceName": "svc"}
    _, err := b.HandleRequest(context.Background(), req)
    require.NoError(t, err)

    // sign zero hash
    zeroHash := hex.EncodeToString(make([]byte, 32))
    req = logical.TestRequest(t, logical.CreateOperation, "key-managers/svc/sign")
    req.Storage = storage
    req.Data = map[string]interface{}{"name": "svc", "hash": zeroHash}
    resp, err := b.HandleRequest(context.Background(), req)
    require.NoError(t, err)
    sig, _ := hex.DecodeString(resp.Data["signature"].(string))
    assert.Len(t, sig, schnorr.SignatureSize)
}
func TestTransferBTC(t *testing.T) {
    b, storage := newTestBackend(t)

    // Create key-manager
    req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
    req.Storage = storage
    req.Data = map[string]interface{}{"serviceName": "svc"}
    _, err := b.HandleRequest(context.Background(), req)
    require.NoError(t, err)

    // Retrieve stored KeyManager to get private key
    entry, err := storage.Get(context.Background(), "key-managers/svc")
    require.NoError(t, err)
    var km KeyManager
    require.NoError(t, entry.DecodeJSON(&km))
    privBytes, err := hex.DecodeString(km.KeyPairs[0].PrivateKey)
    require.NoError(t, err)

    // Dummy BTC transfer: returns base64(privkey) as signed_tx and SHA256(privkey) as txid
    req = logical.TestRequest(t, logical.CreateOperation, "key-managers/svc/txn/btc/transfer")
    req.Storage = storage
    req.Data = map[string]interface{}{"name": "svc"}
    resp, err := b.HandleRequest(context.Background(), req)
    require.NoError(t, err)

    signedB64 := resp.Data["signed_tx"].(string)
    gotBytes, err := base64.StdEncoding.DecodeString(signedB64)
    require.NoError(t, err)
    assert.Equal(t, privBytes, gotBytes)

    sum := sha256.Sum256(privBytes)
    wantTxID := hex.EncodeToString(sum[:])
    assert.Equal(t, wantTxID, resp.Data["txid"].(string))
}
