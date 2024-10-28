// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package nist implements RFC9380 for the NIST P-256, P-384, P-521 groups, and returns points from filippo.io/nistec.
package nist

import (
	"crypto"
	"math/big"
	"sync"

	"filippo.io/nistec"

	"github.com/bytemare/hash2curve"
	"github.com/bytemare/hash2curve/internal"
	"github.com/bytemare/hash2curve/internal/field"
)

const (
	// H2CP256 represents the hash-to-curve string identifier for P256.
	H2CP256 = "P256_XMD:SHA-256_SSWU_RO_"

	// E2CP256 represents the encode-to-curve string identifier for P256.
	E2CP256 = "P256_XMD:SHA-256_SSWU_NU_"

	// H2CP384 represents the hash-to-curve string identifier for P384.
	H2CP384 = "P384_XMD:SHA-384_SSWU_RO_"

	// E2CP384 represents the encode-to-curve string identifier for P384.
	E2CP384 = "P384_XMD:SHA-384_SSWU_NU_"

	// H2CP521 represents the hash-to-curve string identifier for P521.
	H2CP521 = "P521_XMD:SHA-512_SSWU_RO_"

	// E2CP521 represents the encode-to-curve string identifier for P521.
	E2CP521 = "P521_XMD:SHA-512_SSWU_NU_"
)

// HashToP256 implements hash-to-curve mapping to NIST P-256 of input with dst.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func HashToP256(input, dst []byte) *nistec.P256Point {
	initOnceP256.Do(initP256)
	return p256.hashXMD(input, dst)
}

// EncodeToP256 implements encode-to-curve mapping to NIST P-256 of input with dst.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func EncodeToP256(input, dst []byte) *nistec.P256Point {
	initOnceP256.Do(initP256)
	return p256.encodeXMD(input, dst)
}

// HashToScalarP256 returns a safe mapping of the arbitrary input to a scalar for the NIST P-256 group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func HashToScalarP256(input, dst []byte) *big.Int {
	initOnceP256.Do(initP256)
	return hash2curve.HashToFieldXMD(p256.hash, input, dst, 1, 1, p256.secLength, &p256.groupOrder)[0]
}

// HashToP384 implements hash-to-curve mapping to NIST P-384 of input with dst.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func HashToP384(input, dst []byte) *nistec.P384Point {
	initOnceP384.Do(initP384)
	return p384.hashXMD(input, dst)
}

// EncodeToP384 implements encode-to-curve mapping to NIST P-384 of input with dst.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func EncodeToP384(input, dst []byte) *nistec.P384Point {
	initOnceP384.Do(initP384)
	return p384.encodeXMD(input, dst)
}

// HashToScalarP384 returns a safe mapping of the arbitrary input to a scalar for the NIST P-384 group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func HashToScalarP384(input, dst []byte) *big.Int {
	initOnceP384.Do(initP384)
	return hash2curve.HashToFieldXMD(p384.hash, input, dst, 1, 1, p384.secLength, &p384.groupOrder)[0]
}

// HashToP521 implements hash-to-curve mapping to NIST P-521 of input with dst.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func HashToP521(input, dst []byte) *nistec.P521Point {
	initOnceP521.Do(initP521)
	return p521.hashXMD(input, dst)
}

// EncodeToP521 implements encode-to-curve mapping to NIST P-521 of input with dst.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func EncodeToP521(input, dst []byte) *nistec.P521Point {
	initOnceP521.Do(initP521)
	return p521.encodeXMD(input, dst)
}

// HashToScalarP521 returns a safe mapping of the arbitrary input to a scalar for the NIST P-521 group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func HashToScalarP521(input, dst []byte) *big.Int {
	return hash2curve.HashToFieldXMD(p521.hash, input, dst, 1, 1, p521.secLength, &p521.groupOrder)[0]
}

/*
	Internal
*/

var (
	initOnceP256 sync.Once
	initOnceP384 sync.Once
	initOnceP521 sync.Once

	p256 nistCurve[*nistec.P256Point]
	p384 nistCurve[*nistec.P384Point]
	p521 nistCurve[*nistec.P521Point]

	nistWa = big.NewInt(-3)
)

func initP256() {
	primeP256 := new(big.Int).SetBytes([]byte{
		255, 255, 255, 255, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	})
	b := new(big.Int).SetBytes([]byte{
		90, 198, 53, 216, 170, 58, 147, 231, 179, 235, 189, 85, 118, 152, 134, 188,
		101, 29, 6, 176, 204, 83, 176, 246, 59, 206, 60, 62, 39, 210, 96, 75,
	})
	p256.groupOrder = *new(big.Int).SetBytes([]byte{
		255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255,
		188, 230, 250, 173, 167, 23, 158, 132, 243, 185, 202, 194, 252, 99, 37, 81,
	})

	p256.setCurveParams(primeP256, b, nistec.NewP256Point)
	p256.setMapping(crypto.SHA256, -10, 48)
}

func initP384() {
	primeP384 := new(big.Int).SetBytes([]byte{
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255,
		255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255,
	})
	b := new(big.Int).SetBytes([]byte{
		179, 49, 47, 167, 226, 62, 231, 228, 152, 142, 5, 107, 227, 248, 45, 25,
		24, 29, 156, 110, 254, 129, 65, 18, 3, 20, 8, 143, 80, 19, 135, 90, 198,
		86, 57, 141, 138, 46, 209, 157, 42, 133, 200, 237, 211, 236, 42, 239,
	})
	p256.groupOrder = *new(big.Int).SetBytes([]byte{
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 199, 99, 77, 129, 244, 55, 45, 223, 88, 26,
		13, 178, 72, 176, 167, 122, 236, 236, 25, 106, 204, 197, 41, 115,
	})

	p384.setCurveParams(primeP384, b, nistec.NewP384Point)
	p384.setMapping(crypto.SHA384, -12, 72)
}

func initP521() {
	primeP521 := new(big.Int).SetBytes([]byte{
		1, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	})
	b := new(big.Int).SetBytes([]byte{
		81, 149, 62, 185, 97, 142, 28, 154, 31, 146, 154, 33, 160, 182, 133, 64,
		238, 162, 218, 114, 91, 153, 179, 21, 243, 184, 180, 137, 145, 142, 241, 9,
		225, 86, 25, 57, 81, 236, 126, 147, 123, 22, 82, 192, 189, 59, 177, 191,
		7, 53, 115, 223, 136, 61, 44, 52, 241, 239, 69, 31, 212, 107, 80, 63, 0,
	})
	p256.groupOrder = *new(big.Int).SetBytes([]byte{
		1, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 250,
		81, 134, 135, 131, 191, 47, 150, 107, 127, 204, 1, 72, 247, 9, 165, 208, 59,
		181, 201, 184, 137, 156, 71, 174, 187, 111, 183, 30, 145, 56, 100, 9,
	})

	p521.setCurveParams(primeP521, b, nistec.NewP521Point)
	p521.setMapping(crypto.SHA512, -4, 98)
}

type nistECPoint[point any] interface {
	Add(p1, p2 point) point
	Bytes() []byte
	SetBytes(b []byte) (point, error)
}

type mapping struct {
	z         big.Int
	hash      crypto.Hash
	secLength uint
}

type nistCurve[point nistECPoint[point]] struct {
	groupOrder big.Int
	field      field.Field
	b          big.Int
	newPoint   func() point
	mapping
}

func (c *nistCurve[point]) setMapping(hash crypto.Hash, z int, secLength uint) {
	c.mapping.hash = hash
	c.mapping.secLength = secLength
	c.mapping.z = *big.NewInt(int64(z))
}

func (c *nistCurve[point]) setCurveParams(prime, b *big.Int, newPoint func() point) {
	c.field = field.NewField(prime)
	c.b = *b
	c.newPoint = newPoint
}

func (c *nistCurve[point]) encodeXMD(input, dst []byte) point {
	u := hash2curve.HashToFieldXMD(c.hash, input, dst, 1, 1, c.secLength, c.field.Order())
	q := c.map2curve(u[0])
	// We can save cofactor clearing because it is 1.
	return q
}

func (c *nistCurve[point]) hashXMD(input, dst []byte) point {
	u := hash2curve.HashToFieldXMD(c.hash, input, dst, 2, 1, c.secLength, c.field.Order())
	q0 := c.map2curve(u[0])
	q1 := c.map2curve(u[1])

	// We can save cofactor clearing because it is 1.
	return q0.Add(q0, q1)
}

func (c *nistCurve[point]) map2curve(fe *big.Int) point {
	x, y := internal.MapToCurveSSWU(&c.field, nistWa, &c.b, &c.z, fe)
	return c.affineToPoint(x, y)
}

var (
	decompressed256 = [65]byte{0x04}
	decompressed384 = [97]byte{0x04}
	decompressed521 = [133]byte{0x04}
)

func (c *nistCurve[point]) affineToPoint(pxc, pyc *big.Int) point {
	var decompressed []byte

	byteLen := c.field.ByteLen()
	switch byteLen {
	case 32:
		decompressed = decompressed256[:]
	case 48:
		decompressed = decompressed384[:]
	case 66:
		decompressed = decompressed521[:]
	default:
		panic("invalid byte length")
	}

	decompressed[0] = 0x04
	pxc.FillBytes(decompressed[1 : 1+byteLen])
	pyc.FillBytes(decompressed[1+byteLen:])

	p, err := c.newPoint().SetBytes(decompressed)
	if err != nil {
		panic(err)
	}

	return p
}
