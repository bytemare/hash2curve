// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package internal implements the core functionalities for RFC9380 on NIST groups.
package internal

import (
	"crypto"
	"math/big"

	"github.com/bytemare/hash2curve"
	"github.com/bytemare/hash2curve/nist/internal/field"
)

type nistECPoint[point any] interface {
	Add(p1, p2 point) point
	Bytes() []byte
	SetBytes(b []byte) (point, error)
}

type mapping struct {
	b         big.Int
	z         big.Int
	Hash      crypto.Hash
	SecLength uint
}

// NistCurve defines the core characteristics of a NIST curve and its prime-order group.
type NistCurve[point nistECPoint[point]] struct {
	GroupOrder big.Int
	field      field.Field
	newPoint   func() point
	mapping
}

// SetMapping sets the curve's parameters for hash-to-curve.
func (c *NistCurve[point]) SetMapping(hash crypto.Hash, b *big.Int, z int, secLength uint) {
	c.Hash = hash
	c.SecLength = secLength
	c.b = *b
	c.z = *big.NewInt(int64(z))
}

// SetCurveParams sets the curve's field and utility function for a new point.
func (c *NistCurve[point]) SetCurveParams(prime *big.Int, newPoint func() point) {
	c.field = field.NewField(prime)
	c.newPoint = newPoint
}

// EncodeXMD maps input and dst onto a point on the curve.
func (c *NistCurve[point]) EncodeXMD(input, dst []byte) point {
	u := hash2curve.HashToFieldXMD(c.Hash, input, dst, 1, 1, c.SecLength, c.field.Order())
	q := c.map2curve(u[0])
	// We can save cofactor clearing because it is 1.
	return q
}

// HashXMD maps input and dst onto a point on the curve.
func (c *NistCurve[point]) HashXMD(input, dst []byte) point {
	u := hash2curve.HashToFieldXMD(c.Hash, input, dst, 2, 1, c.SecLength, c.field.Order())
	q0 := c.map2curve(u[0])
	q1 := c.map2curve(u[1])

	// We can save cofactor clearing because it is 1.
	return q0.Add(q0, q1)
}

func (c *NistCurve[point]) map2curve(fe *big.Int) point {
	nistWa := big.NewInt(-3)
	x, y := MapToCurveSSWU(&c.field, nistWa, &c.b, &c.z, fe)

	return c.affineToPoint(x, y)
}

func (c *NistCurve[point]) affineToPoint(pxc, pyc *big.Int) point {
	var decompressed []byte

	byteLen := c.field.ByteLen()
	switch byteLen {
	case 32:
		decompressed256 := [65]byte{0x04}
		decompressed = decompressed256[:]
	case 48:
		decompressed384 := [97]byte{0x04}
		decompressed = decompressed384[:]
	case 66:
		decompressed521 := [133]byte{0x04}
		decompressed = decompressed521[:]
	default:
		panic("invalid byte length")
	}

	pxc.FillBytes(decompressed[1 : 1+byteLen])
	pyc.FillBytes(decompressed[1+byteLen:])

	p, err := c.newPoint().SetBytes(decompressed)
	if err != nil {
		panic(err)
	}

	return p
}
