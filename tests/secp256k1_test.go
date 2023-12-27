// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package hash2curve_test

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/bytemare/hash2curve"
	"github.com/bytemare/hash2curve/internal/field"
)

const (
	h2cVectorFiles      = "vectors/h2c"
	suiteNuName         = "secp256k1_XMD:SHA-256_SSWU_NU_"
	suiteRoName         = "secp256k1_XMD:SHA-256_SSWU_RO_"
	secp256k1SecLength  = 48
	elementLength       = 33
	secp256k1FieldOrder = "115792089237316195423570985008687907853269984665640564039457584007908834671663"
)

var (
	fp             = field.NewField(bigString(secp256k1FieldOrder, 10))
	secp256k13ISOA = bigString("0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533", 0)
	secp256k13ISOB = bigString("1771", 0)
	mapZ           = new(big.Int).Mod(big.NewInt(-11), fp.Order())
)

type h2cVectors struct {
	Ciphersuite string      `json:"ciphersuite"`
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

func vectorToSecp256k1(x, y string) []byte {
	var output [33]byte

	yb, _ := hex.DecodeString(y[2:])
	yint := new(big.Int).SetBytes(yb)
	output[0] = byte(2 | yint.Bit(0)&1)

	xb, _ := hex.DecodeString(x[2:])
	copy(output[1:], xb)

	return output[:]
}

func bigString(s string, base int) *big.Int {
	i := new(big.Int)
	if _, ok := i.SetString(s, base); !ok {
		panic(fmt.Sprintf("setting int in base %d failed: %v", base, s))
	}

	return i
}

type element struct {
	x, y big.Int
}

func newElement() *element {
	return &element{
		x: big.Int{},
		y: big.Int{},
	}
}

func newElementWithAffine(x, y *big.Int) *element {
	e := &element{
		x: big.Int{},
		y: big.Int{},
	}

	e.x.Set(x)
	e.y.Set(y)

	return e
}

func (e *element) add(element *element) *element {
	var t0, t1, ll, x, y big.Int
	x1, y1 := e.x, e.y
	x2, y2 := element.x, element.y

	fp.Sub(&t0, &y2, &y1) // (y2-y1)
	fp.Sub(&t1, &x2, &x1) // (x2-x1)
	fp.Inv(&t1, &t1)      // 1/(x2-x1)
	fp.Mul(&ll, &t0, &t1) // l = (y2-y1)/(x2-x1)

	fp.Square(&t0, &ll)   // l^2
	fp.Sub(&t0, &t0, &x1) // l^2-x1
	fp.Sub(&x, &t0, &x2)  // x' = l^2-x1-x2

	fp.Sub(&t0, &x1, &x)  // x1-x3
	fp.Mul(&t0, &t0, &ll) // l(x1-x3)
	fp.Sub(&y, &t0, &y1)  // y3 = l(x1-x3)-y1

	e.x.Set(&x)
	e.y.Set(&y)

	return e
}

func (e *element) IsIdentity() bool {
	return e.x.Sign() == 0 && e.y.Sign() == 0
}

func (e *element) encode() string {
	var output [elementLength]byte

	if e.IsIdentity() {
		return hex.EncodeToString(output[:])
	}

	output[0] = byte(2 | e.y.Bit(0)&1)
	e.x.FillBytes(output[1:])

	return hex.EncodeToString(output[:])
}

func map2IsoCurve(fe *big.Int) *element {
	x, y := hash2curve.MapToCurveSSWU(secp256k13ISOA, secp256k13ISOB, mapZ, fe, fp.Order())
	return newElementWithAffine(x, y)
}

func secp256k1HashToCurve(id crypto.Hash, input, dst string) *element {
	u := hash2curve.HashToFieldXMD(id, []byte(input), []byte(dst), 2, 1, secp256k1SecLength, fp.Order())
	q0 := map2IsoCurve(u[0])
	q1 := map2IsoCurve(u[1])
	q0.add(q1) // we use a generic affine add here because the others are tailored for a = 0 and b = 7.
	x, y, isIdentity := hash2curve.IsogenySecp256k13iso(&q0.x, &q0.y)

	if isIdentity {
		return newElement()
	}

	// We can save cofactor clearing because it is 1.
	return newElementWithAffine(x, y)
}

func secp256k1EncodeToCurve(id crypto.Hash, input, dst string) *element {
	u := hash2curve.HashToFieldXMD(id, []byte(input), []byte(dst), 1, 1, secp256k1SecLength, fp.Order())
	q0 := map2IsoCurve(u[0])
	x, y, isIdentity := hash2curve.IsogenySecp256k13iso(&q0.x, &q0.y)

	if isIdentity {
		return newElement()
	}

	// We can save cofactor clearing because it is 1.
	return newElementWithAffine(x, y)
}

func (v *h2cVector) run(t *testing.T) {
	var expected string

	switch v.Ciphersuite {
	case suiteNuName, suiteRoName:
		expected = hex.EncodeToString(vectorToSecp256k1(v.P.X, v.P.Y))
	default:
		t.Fatal("invalid Group")
	}

	switch v.Ciphersuite[len(v.Ciphersuite)-3:] {
	case "RO_":
		p := secp256k1HashToCurve(crypto.SHA256, v.Msg, v.Dst)

		if encoded := p.encode(); encoded != expected {
			t.Fatalf("Unexpected HashToCurve output.\n\tExpected %q\n\tgot  \t%q", expected, encoded)
		}
	case "NU_":
		p := secp256k1EncodeToCurve(crypto.SHA256, v.Msg, v.Dst)

		if encoded := p.encode(); encoded != expected {
			t.Fatalf("Unexpected EncodeToCurve output.\n\tExpected %q\n\tgot %q", expected, encoded)
		}
	default:
		t.Fatal("ciphersuite not recognized")
	}
}

func (v *h2cVectors) runCiphersuite(t *testing.T) {
	for _, vector := range v.Vectors {
		vector.h2cVectors = v
		t.Run(v.Ciphersuite, vector.run)
	}
}

func TestHashToGroupVectors(t *testing.T) {
	if err := filepath.Walk(h2cVectorFiles,
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
