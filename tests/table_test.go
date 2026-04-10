// SPDX-License-Group: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package hash2curve_test

import (
	"encoding/hex"
	"testing"

	"github.com/bytemare/hash2curve/edwards25519"
	"github.com/bytemare/hash2curve/nist/p256"
	"github.com/bytemare/hash2curve/nist/p384"
	"github.com/bytemare/hash2curve/nist/p521"
	"github.com/bytemare/hash2curve/ristretto255"
	"github.com/bytemare/hash2curve/secp256k1"
)

var (
	testHashToGroupInput = []byte("input data")
	testHashToGroupDST   = []byte("domain separation tag")
)

func TestAll(t *testing.T) {
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.HashToScalar(test.input, test.dst) != test.hashToScalarRef {
				t.Errorf(
					"HashToScalar(%x, %x) = %s, want %s",
					test.input,
					test.dst,
					test.HashToScalar(test.input, test.dst),
					test.hashToScalarRef,
				)
			}
		})
	}
}

type testHashToCurve struct {
	name            string
	HashToScalar    func(input, dst []byte) string
	hashToScalarRef string
	input           []byte
	dst             []byte
}

var tests = []*testHashToCurve{
	{
		name:            "Ristretto255",
		input:           testHashToGroupInput,
		dst:             testHashToGroupDST,
		hashToScalarRef: "7cf9410111022202c71f9d317d6fcd711a84fee5a406063f8376379bbe8a3f03",
		HashToScalar: func(input, dst []byte) string {
			return hex.EncodeToString(ristretto255.HashToScalar(input, dst).Bytes())
		},
	},
	{
		name:            "P256",
		input:           testHashToGroupInput,
		dst:             testHashToGroupDST,
		hashToScalarRef: "4b51fd1148439c3a30539e87a2a75c63d72f71b74d108184beeb933d259456b9",
		HashToScalar: func(input, dst []byte) string {
			return hex.EncodeToString(p256.HashToScalar(input, dst).Bytes())
		},
	},
	{
		name:            "P384",
		input:           testHashToGroupInput,
		dst:             testHashToGroupDST,
		hashToScalarRef: "d22b5352caa675f8a2f385236b95cbc1f84b9e34540b3587d6d55bd5032bf51aeb54ccab701c6f05a489b82ec301012d",
		HashToScalar: func(input, dst []byte) string {
			return hex.EncodeToString(p384.HashToScalar(input, dst).Bytes())
		},
	},
	{
		name:            "P521",
		input:           testHashToGroupInput,
		dst:             testHashToGroupDST,
		hashToScalarRef: "01f4e5806586dbebd01e85b17da1eb2df4ac678bc8683b9baa5dd5fba6a0f9d1ff5621ed342a90273150fd095c7abc07f97d202183ec804d063b9fcc0b95daec0614",
		HashToScalar: func(input, dst []byte) string {
			return hex.EncodeToString(p521.HashToScalar(input, dst).Bytes())
		},
	},
	{
		name:            "Edwards25519",
		input:           testHashToGroupInput,
		dst:             testHashToGroupDST,
		hashToScalarRef: "90249f56fa61b29fc09b8787d9954a6beba6ca49e25c80f78560ca5458e5b807",
		HashToScalar: func(input, dst []byte) string {
			return hex.EncodeToString(edwards25519.HashToScalar(input, dst).Bytes())
		},
	},
	{
		name:            "secp256k1",
		input:           testHashToGroupInput,
		dst:             testHashToGroupDST,
		hashToScalarRef: "782a63d48eace435ac06468208d9a62e3680e4ddc3977c4345b2c6de08258b69",
		HashToScalar: func(input, dst []byte) string {
			return secp256k1.HashToScalar(input, dst).Hex()
		},
	},
}
