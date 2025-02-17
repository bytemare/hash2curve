// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package p521 implements RFC9380 for the P521 group.
package p521

import (
	"crypto"
	"math/big"
	"sync"

	"filippo.io/nistec"

	"github.com/bytemare/hash2curve"
	"github.com/bytemare/hash2curve/nist/internal"
)

const (
	// H2CP521 represents the hash-to-curve string identifier for P521.
	H2CP521 = "P521_XMD:SHA-512_SSWU_RO_"

	// E2CP521 represents the encode-to-curve string identifier for P521.
	E2CP521 = "P521_XMD:SHA-512_SSWU_NU_"
)

var (
	initOnceP521 sync.Once
	p521         internal.NistCurve[*nistec.P521Point]
)

// HashToCurve implements hash-to-curve mapping to P521 of input with dst.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func HashToCurve(input, dst []byte) *nistec.P521Point {
	initOnceP521.Do(initP521)
	return p521.HashXMD(input, dst)
}

// EncodeToCurve implements encode-to-curve mapping to P521 of input with dst.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func EncodeToCurve(input, dst []byte) *nistec.P521Point {
	initOnceP521.Do(initP521)
	return p521.EncodeXMD(input, dst)
}

// HashToScalar returns a safe mapping of the arbitrary input to a scalar for the prime-order group of P521.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func HashToScalar(input, dst []byte) *big.Int {
	initOnceP521.Do(initP521)
	return hash2curve.HashToFieldXMD(p521.Hash, input, dst, 1, 1, p521.SecLength, &p521.GroupOrder)[0]
}

func initP521() {
	primeP521 := new(big.Int).SetBytes([]byte{
		1, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	})
	b := new(big.Int).SetBytes([]byte{
		81, 149, 62, 185, 97, 142, 28, 154, 31, 146, 154, 33, 160, 182, 133, 64,
		238, 162, 218, 114, 91, 153, 179, 21, 243, 184, 180, 137, 145, 142, 241, 9,
		225, 86, 25, 57, 81, 236, 126, 147, 123, 22, 82, 192, 189, 59, 177, 191,
		7, 53, 115, 223, 136, 61, 44, 52, 241, 239, 69, 31, 212, 107, 80, 63, 0,
	})
	p521.GroupOrder = *new(big.Int).SetBytes([]byte{
		1, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 250,
		81, 134, 135, 131, 191, 47, 150, 107, 127, 204, 1, 72, 247, 9, 165, 208, 59,
		181, 201, 184, 137, 156, 71, 174, 187, 111, 183, 30, 145, 56, 100, 9,
	})

	p521.SetCurveParams(primeP521, nistec.NewP521Point)
	p521.SetMapping(crypto.SHA512, b, -4, 98)
}
