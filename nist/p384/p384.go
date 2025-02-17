// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package p384 implements RFC9380 for the P384 group.
package p384

import (
	"crypto"
	"math/big"
	"sync"

	"filippo.io/nistec"

	"github.com/bytemare/hash2curve"
	"github.com/bytemare/hash2curve/nist/internal"
)

const (
	// H2CP384 represents the hash-to-curve string identifier for P384.
	H2CP384 = "P384_XMD:SHA-384_SSWU_RO_"

	// E2CP384 represents the encode-to-curve string identifier for P384.
	E2CP384 = "P384_XMD:SHA-384_SSWU_NU_"
)

var (
	initOnceP384 sync.Once
	p384         internal.NistCurve[*nistec.P384Point]
)

// HashToCurve implements hash-to-curve mapping to P384 of input with dst.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func HashToCurve(input, dst []byte) *nistec.P384Point {
	initOnceP384.Do(initP384)
	return p384.HashXMD(input, dst)
}

// EncodeToCurve implements encode-to-curve mapping to P384 of input with dst.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func EncodeToCurve(input, dst []byte) *nistec.P384Point {
	initOnceP384.Do(initP384)
	return p384.EncodeXMD(input, dst)
}

// HashToScalar returns a safe mapping of the arbitrary input to a scalar for the prime-order group of P384.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func HashToScalar(input, dst []byte) *big.Int {
	initOnceP384.Do(initP384)
	return hash2curve.HashToFieldXMD(p384.Hash, input, dst, 1, 1, p384.SecLength, &p384.GroupOrder)[0]
}

func initP384() {
	primeP384 := new(big.Int).SetBytes([]byte{
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255,
		255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255,
	})
	b := new(big.Int).SetBytes([]byte{
		179, 49, 47, 167, 226, 62, 231, 228, 152, 142, 5, 107, 227, 248, 45, 25,
		24, 29, 156, 110, 254, 129, 65, 18, 3, 20, 8, 143, 80, 19, 135, 90, 198,
		86, 57, 141, 138, 46, 209, 157, 42, 133, 200, 237, 211, 236, 42, 239,
	})
	p384.GroupOrder = *new(big.Int).SetBytes([]byte{
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 199, 99, 77, 129, 244, 55, 45, 223, 88, 26,
		13, 178, 72, 176, 167, 122, 236, 236, 25, 106, 204, 197, 41, 115,
	})

	p384.SetCurveParams(primeP384, nistec.NewP384Point)
	p384.SetMapping(crypto.SHA384, b, -12, 72)
}
