// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package hash2curve provides hash-to-curve compatible hashing over arbitrary input.
package hash2curve

import (
	"crypto"
	"errors"

	"github.com/bytemare/hash"

	"github.com/bytemare/hash2curve/internal"
)

const (
	minLength            = 0
	recommendedMinLength = 16
)

var errZeroLenDST = errors.New("zero-length DST")

func checkDST(dst []byte) {
	if len(dst) < recommendedMinLength {
		if len(dst) == minLength {
			panic(errZeroLenDST)
		}
	}
}

// ExpandXMD expands the input and dst using the given fixed length hash function.
func ExpandXMD(id crypto.Hash, input, dst []byte, length int) []byte {
	checkDST(dst)
	return internal.ExpandXMD(id, input, dst, length)
}

// ExpandXOF expands the input and dst using the given extendable output hash function.
func ExpandXOF(ext *hash.ExtendableHash, input, dst []byte, length int) []byte {
	checkDST(dst)
	return internal.ExpandXOF(ext, input, dst, length)
}
