package sgx_server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

func TestECDHAndKeyDerivation(t *testing.T) {
	// The inputs to this were generated using Python
	p1 := "410e56df2bf25cb4008689565e359e0869def9393ddc57f0c6beccfb99bec136"
	x1 := "0d670402220a94374fb0803ca4fbd7d9d5a43fd8850ffd92602aa7dcf5f70034"
	y1 := "c919eca19436f2d9172831075ffb449e16b3a550be7995b43895e5c8cad659ac"
	// p2 := "26f9e05950891b06f8f94d4b0b2e675d1bc5d956508d11ac193abebce7834b9e"
	x2 := "46c25c041be5fe65390f9cd71b0a656359e8def156316a4300a726ab8eb86ea4"
	y2 := "0d6b405fca6192700ed19188ea6486b5fbaa1ea4a3d8bbd46152ee1f8bfc1f9d"
	// expected derived keys
	kdk := "7082b5102f5080aba92afb1e3f6c9991"
	derivedKey := "2c81f49a644efcaedba530276fe8e268"
	kb, err := hex.DecodeString(kdk)
	if err != nil {
		t.Fatal(err)
	}
	db, err := hex.DecodeString(derivedKey)
	if err != nil {
		t.Fatal(err)
	}

	priv1, err := hex.DecodeString(p1)
	if err != nil {
		t.Fatal(err)
	}
	xb1, err := hex.DecodeString(x1)
	if err != nil {
		t.Fatal(err)
	}
	yb1, err := hex.DecodeString(y1)
	if err != nil {
		t.Fatal(err)
	}
	xb2, err := hex.DecodeString(x2)
	if err != nil {
		t.Fatal(err)
	}
	yb2, err := hex.DecodeString(y2)
	if err != nil {
		t.Fatal(err)
	}

	pub1, err := unmarshalPublicKey(xb1, yb1)
	if err != nil {
		t.Fatal(err)
	}

	pub2, err := unmarshalPublicKey(xb2, yb2)
	if err != nil {
		t.Fatal(err)
	}

	curve := elliptic.P256()
	if !curve.IsOnCurve(pub1.X, pub1.Y) || !curve.IsOnCurve(pub2.X, pub2.Y) {
		t.Fatal("Point not on the curve.")
	}

	// private key is little endian encoded, so change to them to big
	reverse(priv1)
	D := new(big.Int)
	D.SetBytes(priv1)

	mine := &ecdsa.PrivateKey{
		PublicKey: *pub1,
		D:         D,
	}

	baseKey, labelKey := deriveLabelKey(mine, pub2, []byte("helloworld"))
	if !bytes.Equal(baseKey, kb) {
		fmt.Println(kb)
		fmt.Println(baseKey)
		t.Error("Base key derivation failed.")
	}

	if !bytes.Equal(labelKey, db) {
		fmt.Println(db)
		fmt.Println(labelKey)
		t.Error("Label key derivation failed.")
	}
}
