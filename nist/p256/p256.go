// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package p256 implements RFC9380 for the P256 group.
package p256

import (
	"crypto"
	"math/big"
	"sync"

	"filippo.io/nistec"

	"github.com/bytemare/hash2curve"
	"github.com/bytemare/hash2curve/nist/internal"
)

const (
	// H2CP256 represents the hash-to-curve string identifier for P256.
	H2CP256 = "P256_XMD:SHA-256_SSWU_RO_"

	// E2CP256 represents the encode-to-curve string identifier for P256.
	E2CP256 = "P256_XMD:SHA-256_SSWU_NU_"
)

var (
	initOnceP256 sync.Once
	p256         internal.NistCurve[*nistec.P256Point]
)

// HashToCurve implements hash-to-curve mapping to P256 of input with dst.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func HashToCurve(input, dst []byte) *nistec.P256Point {
	initOnceP256.Do(initP256)
	return p256.HashXMD(input, dst)
}

// EncodeToCurve implements encode-to-curve mapping to P256 of input with dst.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func EncodeToCurve(input, dst []byte) *nistec.P256Point {
	initOnceP256.Do(initP256)
	return p256.EncodeXMD(input, dst)
}

// HashToScalar returns a safe mapping of the arbitrary input to a scalar for the prime-order group of P256.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func HashToScalar(input, dst []byte) *big.Int {
	initOnceP256.Do(initP256)
	return hash2curve.HashToFieldXMD(p256.Hash, input, dst, 1, 1, p256.SecLength, &p256.GroupOrder)[0]
}

func initP256() {
	primeP256 := new(big.Int).SetBytes([]byte{
		255, 255, 255, 255, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	})
	b := new(big.Int).SetBytes([]byte{
		90, 198, 53, 216, 170, 58, 147, 231, 179, 235, 189, 85, 118, 152, 134, 188,
		101, 29, 6, 176, 204, 83, 176, 246, 59, 206, 60, 62, 39, 210, 96, 75,
	})
	p256.GroupOrder = *new(big.Int).SetBytes([]byte{
		255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255,
		188, 230, 250, 173, 167, 23, 158, 132, 243, 185, 202, 194, 252, 99, 37, 81,
	})

	p256.SetCurveParams(primeP256, nistec.NewP256Point)
	p256.SetMapping(crypto.SHA256, b, -10, 48)
}
