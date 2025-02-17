// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package secp256k1 implements RFC9380 for the secp256k1 group.
package secp256k1

import "github.com/bytemare/secp256k1"

const (
	// H2C represents the hash-to-curve string identifier for secp256k1.
	H2C = "secp256k1_XMD:SHA-256_SSWU_RO_"

	// E2C represents the encode-to-curve string identifier for secp256k1.
	E2C = "secp256k1_XMD:SHA-256_SSWU_NU_"
)

// HashToCurve implements hash-to-curve mapping to secp256k1 of input with dst.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func HashToCurve(input, dst []byte) *secp256k1.Element {
	return secp256k1.HashToGroup(input, dst)
}

// EncodeToCurve implements encode-to-curve mapping to secp256k1 of input with dst.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func EncodeToCurve(input, dst []byte) *secp256k1.Element {
	return secp256k1.EncodeToGroup(input, dst)
}

// HashToScalar returns a safe mapping of the arbitrary input to a scalar for the prime-order group of secp256k1.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func HashToScalar(input, dst []byte) *secp256k1.Scalar {
	return secp256k1.HashToScalar(input, dst)
}
