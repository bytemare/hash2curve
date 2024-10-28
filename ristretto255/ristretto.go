// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package ristretto255 implements RFC9380 for the ristretto255 group, and returns points and scalar from
// github.com/gtank/ristretto255.
package ristretto255

import (
	"crypto"

	"github.com/gtank/ristretto255"

	"github.com/bytemare/hash2curve"
)

// HashToGroup returns a safe mapping of the arbitrary input to an Element in the Ristretto255 group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func HashToGroup(input, dst []byte) *ristretto255.Element {
	uniform := hash2curve.ExpandXMD(crypto.SHA512, input, dst, 64)
	return ristretto255.NewElement().FromUniformBytes(uniform)
}

// EncodeToGroup returns a non-uniform mapping of the arbitrary input to an Element in the Ristretto255 group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func EncodeToGroup(input, dst []byte) *ristretto255.Element {
	return HashToGroup(input, dst)
}

// HashToScalar returns a safe mapping of the arbitrary input to a Scalar.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func HashToScalar(input, dst []byte) *ristretto255.Scalar {
	uniform := hash2curve.ExpandXMD(crypto.SHA512, input, dst, 64)
	return ristretto255.NewScalar().FromUniformBytes(uniform)
}
