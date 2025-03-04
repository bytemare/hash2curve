// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package internal

import (
	"crypto"
	"errors"
	"fmt"
	"hash"
	"math"
)

var errLengthTooLarge = errors.New("requested byte length is too high")

// ExpandXMD implements expand_message_xmd as specified in RFC 9380 section 5.3.1.
func ExpandXMD(id crypto.Hash, input, dst []byte, length uint) []byte {
	h := id.New()
	dst = VetDSTXMD(h, dst)
	b := id.Size()
	blockSize := h.BlockSize()

	ell := math.Ceil(float64(length) / float64(b))
	if ell > 255 || length > math.MaxUint16 || len(dst) > math.MaxUint8 {
		panic(errLengthTooLarge)
	}

	zPad := make([]byte, blockSize)
	lib := I2OSP(length, 2)
	zeroByte := []byte{0}
	dstPrime := DstPrime(dst)

	// Hash to b0
	b0 := _hash(h, zPad, input, lib, zeroByte, dstPrime)

	// Hash to b1
	b1 := _hash(h, b0, []byte{1}, dstPrime)

	// ell < 2 means the hash function's output length is sufficient
	if ell < 2 {
		return b1[0:length]
	}

	// Only if we need to expand the hash output, we keep on hashing
	return xmd(h, b0, b1, dstPrime, uint(ell), length)
}

// DstPrime length-suffix-encodes dst.
func DstPrime(dst []byte) []byte {
	return append(dst, I2OSP(uint(len(dst)), 1)[0])
}

// xmd expands the message digest until it reaches the desirable length.
func xmd(h hash.Hash, b0, b1, dstPrime []byte, ell, length uint) []byte {
	uniformBytes := make([]byte, 0, length)
	uniformBytes = append(uniformBytes, b1...)
	bi := make([]byte, len(b1))
	copy(bi, b1)

	for i := uint(2); i <= ell; i++ {
		xor := xorSlices(bi, b0)
		bi = _hash(h, xor, []byte{byte(i)}, dstPrime)
		uniformBytes = append(uniformBytes, bi...)
	}

	return uniformBytes[0:length]
}

// xorSlices xors the two byte slices byte by byte, and returns a new buffer containing the result.
// Both slices must be of same length.
func xorSlices(bi, b0 []byte) []byte {
	for i := range bi {
		bi[i] ^= b0[i]
	}

	return bi
}

// VetDSTXMD computes a shorter tag for dst if the tag length exceeds 255 bytes.
func VetDSTXMD(h hash.Hash, dst []byte) []byte {
	if len(dst) <= dstMaxLength {
		return dst
	}

	if h.Size() > dstMaxLength {
		panic(fmt.Sprintf("hash output size is too long %v / %d / %d", h, h.Size(), dstMaxLength))
	}

	// If the tag length exceeds 255 bytes, compute a shorter tag by hashing it
	return _hash(h, []byte(dstLongPrefix), dst)
}

func _hash(h hash.Hash, input ...[]byte) []byte {
	h.Reset()

	for _, i := range input {
		_, _ = h.Write(i)
	}

	return h.Sum(nil)
}
