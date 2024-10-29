// SPDX-License-Group: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package hash2curve_test

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"

	"github.com/bytemare/hash2curve"
	edwards25520 "github.com/bytemare/hash2curve/edwards25519"
	"github.com/bytemare/hash2curve/nist"
	"github.com/bytemare/hash2curve/secp256k1"
)

const (
	hashToCurveVectorsFileLocation = "vectors/h2c"

	p256SecLength = 48
	p384SecLength = 72
	p521SecLength = 98
)

var (
	prime25519 = new(big.Int).SetBytes([]byte{
		127, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 237,
	})
	primeP256 = new(big.Int).SetBytes([]byte{
		255, 255, 255, 255, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	})
	primeP384 = new(big.Int).SetBytes([]byte{
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255,
		255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255,
	})
	primeP521 = new(big.Int).SetBytes([]byte{
		1, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	})
	primeSecp256k1 = new(big.Int).SetBytes([]byte{
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 252, 47,
	})
)

// const hashToCurveVectorsFileLocation = "h2c"
type h2cVectors struct {
	Ciphersuite string      `json:"ciphersuite"`
	Curve       string      `json:"curve"`
	Dst         string      `json:"dst"`
	Vectors     []h2cVector `json:"vectors"`
}

type h2cVector struct {
	*h2cVectors
	P struct {
		X string `json:"x"`
		Y string `json:"y"`
	} `json:"P"`
	Q0 struct {
		X string `json:"x"`
		Y string `json:"y"`
	} `json:"Q0"`
	Q1 struct {
		X string `json:"x"`
		Y string `json:"y"`
	} `json:"Q1"`
	Msg string   `json:"msg"`
	U   []string `json:"u"`
}

func ecFromString(c string) elliptic.Curve {
	switch c {
	case "NIST P-256":
		return elliptic.P256()
	case "NIST P-384":
		return elliptic.P384()
	case "NIST P-521":
		return elliptic.P521()
	default:
		panic("invalid nist group")
	}
}

func vectorToBig(x, y string) (*big.Int, *big.Int) {
	xb, ok := new(big.Int).SetString(x, 0)
	if !ok {
		panic("invalid x")
	}

	yb, ok := new(big.Int).SetString(y, 0)
	if !ok {
		panic("invalid y")
	}

	return xb, yb
}

func affineToEdwardsFromStrings(t *testing.T, a string) *field.Element {
	aBytes, err := hex.DecodeString(a[2:])
	if err != nil {
		t.Fatal(err)
	}

	// reverse
	for i, j := 0, len(aBytes)-1; j > i; i++ {
		aBytes[i], aBytes[j] = aBytes[j], aBytes[i]
		j--
	}

	u := &field.Element{}
	if _, err := u.SetBytes(aBytes); err != nil {
		t.Fatal(err)
	}

	return u
}

func affineToEdwards(x, y *field.Element) *edwards25519.Point {
	t := new(field.Element).Multiply(x, y)

	p, err := new(edwards25519.Point).SetExtendedCoordinates(x, y, new(field.Element).One(), t)
	if err != nil {
		panic(err)
	}

	return p
}

func vectorToEdwards25519(t *testing.T, x, y string) *edwards25519.Point {
	u, v := affineToEdwardsFromStrings(t, x), affineToEdwardsFromStrings(t, y)
	return affineToEdwards(u, v)
}

func vectorToSecp256k1(x, y string) []byte {
	var output [33]byte

	yb, _ := hex.DecodeString(y[2:])
	yint := new(big.Int).SetBytes(yb)
	output[0] = byte(2 | yint.Bit(0)&1)

	xb, _ := hex.DecodeString(x[2:])
	copy(output[1:], xb)

	return output[:]
}

func (v *h2cVector) run(t *testing.T) {
	var b, expected []byte
	var h2c, e2c string
	mode := v.Ciphersuite[len(v.Ciphersuite)-3:]
	var u []*big.Int

	switch v.Curve {
	case "NIST P-256", "NIST P-384", "NIST P-521":
		e := ecFromString(v.Curve)
		x, y := vectorToBig(v.P.X, v.P.Y)
		expected = elliptic.MarshalCompressed(e, x, y)

		if mode == "RO_" {
			switch v.Curve {
			case "NIST P-256":
				h2c = nist.H2CP256
				p := nist.HashToP256([]byte(v.Msg), []byte(v.Dst))
				b = p.BytesCompressed()
				u = hash2curve.HashToFieldXMD(
					crypto.SHA256,
					[]byte(v.Msg),
					[]byte(v.Dst),
					2,
					1,
					p256SecLength,
					primeP256,
				)
			case "NIST P-384":
				h2c = nist.H2CP384
				p := nist.HashToP384([]byte(v.Msg), []byte(v.Dst))
				b = p.BytesCompressed()
				u = hash2curve.HashToFieldXMD(
					crypto.SHA384,
					[]byte(v.Msg),
					[]byte(v.Dst),
					2,
					1,
					p384SecLength,
					primeP384,
				)
			case "NIST P-521":
				h2c = nist.H2CP521
				p := nist.HashToP521([]byte(v.Msg), []byte(v.Dst))
				b = p.BytesCompressed()
				u = hash2curve.HashToFieldXMD(
					crypto.SHA512,
					[]byte(v.Msg),
					[]byte(v.Dst),
					2,
					1,
					p521SecLength,
					primeP521,
				)
			}

			if v.Ciphersuite != h2c {
				t.Fatal("unexpected h2c")
			}
		} else {
			switch v.Curve {
			case "NIST P-256":
				e2c = nist.E2CP256
				p := nist.EncodeToP256([]byte(v.Msg), []byte(v.Dst))
				b = p.BytesCompressed()
				u = hash2curve.HashToFieldXMD(crypto.SHA256, []byte(v.Msg), []byte(v.Dst), 1, 1, p256SecLength, primeP256)
			case "NIST P-384":
				e2c = nist.E2CP384
				p := nist.EncodeToP384([]byte(v.Msg), []byte(v.Dst))
				b = p.BytesCompressed()
				u = hash2curve.HashToFieldXMD(crypto.SHA384, []byte(v.Msg), []byte(v.Dst), 1, 1, p384SecLength, primeP384)
			case "NIST P-521":
				e2c = nist.E2CP521
				p := nist.EncodeToP521([]byte(v.Msg), []byte(v.Dst))
				b = p.BytesCompressed()
				u = hash2curve.HashToFieldXMD(crypto.SHA512, []byte(v.Msg), []byte(v.Dst), 1, 1, p521SecLength, primeP521)
			}

			if v.Ciphersuite != e2c {
				t.Fatalf("unexpected e2c: %s/%s", v.Ciphersuite, e2c)
			}
		}

	case "edwards25519":
		edPoint := vectorToEdwards25519(t, v.P.X, v.P.Y)
		expected = edPoint.Bytes()
		if mode == "RO_" {
			if v.Ciphersuite != edwards25520.H2C {
				t.Fatal("unexpected h2c")
			}

			p := edwards25520.HashToCurve([]byte(v.Msg), []byte(v.Dst))
			b = p.Bytes()
			u = hash2curve.HashToFieldXMD(crypto.SHA512, []byte(v.Msg), []byte(v.Dst), 2, 1, 48, prime25519)
		} else {
			if v.Ciphersuite != edwards25520.E2C {
				t.Fatal("unexpected e2c")
			}

			p := edwards25520.EncodeToCurve([]byte(v.Msg), []byte(v.Dst))
			b = p.Bytes()
			u = hash2curve.HashToFieldXMD(crypto.SHA512, []byte(v.Msg), []byte(v.Dst), 1, 1, 48, prime25519)
		}

	case "secp256k1":
		expected = vectorToSecp256k1(v.P.X, v.P.Y)
		if mode == "RO_" {
			if v.Ciphersuite != secp256k1.H2C {
				t.Fatal("unexpected h2c")
			}

			p := secp256k1.HashToCurve([]byte(v.Msg), []byte(v.Dst))
			b = p.Bytes()
			u = hash2curve.HashToFieldXMD(crypto.SHA256, []byte(v.Msg), []byte(v.Dst), 2, 1, 48, primeSecp256k1)
		} else {
			if v.Ciphersuite != secp256k1.E2C {
				t.Fatal("unexpected e2c")
			}

			p := secp256k1.EncodeToCurve([]byte(v.Msg), []byte(v.Dst))
			b = p.Bytes()
			u = hash2curve.HashToFieldXMD(crypto.SHA256, []byte(v.Msg), []byte(v.Dst), 1, 1, 48, primeSecp256k1)
		}
	default:
		t.Fatalf("unexpected curve %s", v.Curve)
	}

	// verify hash to field
	if len(v.U) != len(u) {
		t.Fatalf("invalid length of u field elements %d/%d", len(v.U), len(u))
	}

	for i, h := range v.U {
		if !strings.HasSuffix(h, hex.EncodeToString(u[i].Bytes())) {
			t.Fatalf("expected equality\n%s\n%s", h[2:], hex.EncodeToString(u[i].Bytes()))
		}
	}

	// verify encoding and hashing
	if err := verifyEncoding(mode, b, expected); err != nil {
		t.Fatal(err)
	}
}

func verifyEncoding(function string, output, expected []byte) error {
	if !bytes.Equal(output, expected) {
		return fmt.Errorf("Unexpected %s output.\n\tExpected %q\n\tgot %q",
			function,
			hex.EncodeToString(expected),
			hex.EncodeToString(output),
		)
	}

	return nil
}

func (v *h2cVectors) runCiphersuite(t *testing.T) {
	for _, vector := range v.Vectors {
		vector.h2cVectors = v
		t.Run(v.Ciphersuite, vector.run)
	}
}

func TestHashToGroupVectors(t *testing.T) {
	if err := filepath.Walk(hashToCurveVectorsFileLocation,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}
			file, errOpen := os.Open(path)
			if errOpen != nil {
				t.Fatal(errOpen)
			}

			defer func(file *os.File) {
				err := file.Close()
				if err != nil {
					t.Logf("error closing file: %v", err)
				}
			}(file)

			val, errRead := io.ReadAll(file)
			if errRead != nil {
				t.Fatal(errRead)
			}

			var v h2cVectors
			errJSON := json.Unmarshal(val, &v)
			if errJSON != nil {
				t.Fatal(errJSON)
			}

			t.Run(v.Ciphersuite, v.runCiphersuite)

			return nil
		}); err != nil {
		t.Fatalf("error opening vector files: %v", err)
	}
}
