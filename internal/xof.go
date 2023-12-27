// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package internal values, structures, and functions that are not part of the public API.
package internal

import (
	"errors"
	"math"

	"github.com/bytemare/hash"
)

var errXOFHighOutput = errors.New("XOF dst hashing is too long")

// ExpandXOF implements expand_message_xof as specified in RFC 9380 section 5.3.2.
func ExpandXOF(ext *hash.ExtendableHash, input, dst []byte, length int) []byte {
	if length > math.MaxUint16 {
		panic(errLengthTooLarge)
	}

	dst = VetXofDST(ext, dst)
	len2o := I2osp(length, 2)
	dstLen2o := I2osp(len(dst), 1)

	return ext.Hash(length, input, len2o, dst, dstLen2o)
}

// VetXofDST computes a shorter tag for dst if the tag length exceeds 255 bytes.
func VetXofDST(x *hash.ExtendableHash, dst []byte) []byte {
	if len(dst) <= dstMaxLength {
		return dst
	}

	k := x.Algorithm().SecurityLevel()

	size := int(math.Ceil(float64(2*k) / float64(8)))
	if size > math.MaxUint8 {
		panic(errXOFHighOutput)
	}

	return x.Hash(size, []byte(dstLongPrefix), dst)
}
