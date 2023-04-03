// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package hash2curve provides hash-to-curve compatible input expansion.
package hash2curve

import (
	"crypto"

	"filippo.io/bigmod"
	"github.com/bytemare/hash"
)

// HashToFieldXOF hashes the input with the domain separation tag (dst) to an integer under modulo, using an
// extensible output function (e.g. SHAKE).
func HashToFieldXOF(
	id hash.Extendable,
	input, dst []byte,
	count, ext, securityLength int,
	modulo *bigmod.Modulus,
) []*bigmod.Nat {
	expLength := count * ext * securityLength // elements * ext * security length
	uniform := ExpandXOF(id, input, dst, expLength)

	return reduceUniform(uniform, count, securityLength, modulo)
}

// HashToFieldXMD hashes the input with the domain separation tag (dst) to an integer under modulo, using an
// merkle-damgard based expander (e.g. SHA256).
func HashToFieldXMD(
	id crypto.Hash,
	input, dst []byte,
	count, ext, securityLength int,
	modulo *bigmod.Modulus,
) []*bigmod.Nat {
	expLength := count * ext * securityLength // elements * ext * security length
	uniform := ExpandXMD(id, input, dst, expLength)

	return reduceUniform(uniform, count, securityLength, modulo)
}

func reduceUniform(uniform []byte, count, securityLength int, modulo *bigmod.Modulus) []*bigmod.Nat {
	res := make([]*bigmod.Nat, count)

	for i := 0; i < count; i++ {
		offset := i * securityLength
		res[i] = reduce(uniform[offset:offset+securityLength], modulo)
	}

	return res
}

func reduce(input []byte, modulo *bigmod.Modulus) *bigmod.Nat {
	/*
		Interpret the input as a big-endian encoded unsigned integer of the field, and reduce it modulo the prime.
	*/
	i, err := bigmod.NewNat().SetBytes(input, modulo)
	if err != nil {
		panic(err)
	}

	return i
}
