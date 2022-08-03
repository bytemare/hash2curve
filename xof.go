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
	"errors"
	"math"

	"github.com/bytemare/hash"
)

var errXOFHighOutput = errors.New("XOF dst hashing is too long")

// expandMessage XOF implements https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve#section-5.4.2.
func expandXOF(x hash.Extendable, input, dst []byte, length int) []byte {
	if length > math.MaxUint16 {
		panic(errLengthTooLarge)
	}

	dst = vetXofDST(x, dst)
	len2o := i2osp(length, 2)
	dstLen2o := i2osp(len(dst), 1)

	return x.Get().Hash(length, input, len2o, dst, dstLen2o)
}

// If the tag length exceeds 255 bytes, compute a shorter tag by hashing it.
func vetXofDST(x hash.Extendable, dst []byte) []byte {
	if len(dst) <= dstMaxLength {
		return dst
	}

	k := x.SecurityLevel()

	size := int(math.Ceil(float64(2*k) / float64(8)))
	if size > math.MaxUint8 {
		panic(errXOFHighOutput)
	}

	return x.Get().Hash(size, []byte(dstLongPrefix), dst)
}
