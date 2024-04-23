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
	"math"
	"math/big"
	"testing"

	"github.com/bytemare/hash"

	"github.com/bytemare/hash2curve"
)

func fuzzTestSkipInput(t *testing.T, dst []byte, length uint) {
	if len(dst) == 0 {
		t.Skip("zero length dst")
	}

	if length < 0 {
		t.Skip("requested length is negative")
	}

	if length > math.MaxUint16 {
		t.Skip("requested length too big")
	}
}

func fuzzTestSkipXMDInput(t *testing.T, h uint, dst []byte, length uint) {
	fuzzTestSkipInput(t, dst, length)

	hid := crypto.Hash(h)

	if !hid.Available() {
		t.Skip("unavailable hash")
	}

	if len(dst) > math.MaxUint8 {
		t.Skip("dst too long")
	}

	if length > uint(255*hid.Size()) {
		t.Skip("requested length too big")
	}
}

func FuzzExpandXMD(f *testing.F) {
	f.Fuzz(func(t *testing.T, h uint, input, dst []byte, length uint) {
		fuzzTestSkipXMDInput(t, h, dst, length)
		_ = hash2curve.ExpandXMD(crypto.Hash(h), input, dst, length)
	})
}

func FuzzHashToFieldXMD(f *testing.F) {
	f.Fuzz(func(t *testing.T, id uint, input, dst []byte, count, ext, securityLength uint, modulo int64) {
		fuzzTestSkipXMDInput(t, id, dst, count*ext*securityLength)
		_ = hash2curve.HashToFieldXMD(crypto.Hash(id), input, dst, count, ext, securityLength, big.NewInt(modulo))
	})
}

func fuzzTestSkipXOFInput(t *testing.T, h uint, dst []byte, length uint) {
	fuzzTestSkipInput(t, dst, length)

	if hash.Hash(h) < hash.SHAKE128 || hash.Hash(h) > hash.BLAKE2XS {
		t.Skip()
	}

	if length < 32 {
		t.Skip("length too small")
	}

	if !hash.Hash(h).Available() {
		t.Skip()
	}
}

func FuzzExpandXOF(f *testing.F) {
	f.Fuzz(func(t *testing.T, h uint, input, dst []byte, length uint) {
		fuzzTestSkipXOFInput(t, h, dst, length)
		_ = hash2curve.ExpandXOF(hash.Hash(h).GetXOF(), input, dst, length)
	})
}

func FuzzHashToFieldXOF(f *testing.F) {
	f.Fuzz(func(t *testing.T, id uint, input, dst []byte, count, ext, securityLength uint, modulo int64) {
		fuzzTestSkipXOFInput(t, id, dst, count*ext*securityLength)
		_ = hash2curve.HashToFieldXOF(
			hash.Hash(id).GetXOF(),
			input,
			dst,
			count,
			ext,
			securityLength,
			big.NewInt(modulo),
		)
	})
}
