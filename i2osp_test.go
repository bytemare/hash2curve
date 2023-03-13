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
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

var (
	errNoPanic        = errors.New("no panic")
	errNoPanicMessage = errors.New("panic but no message")
)

func hasPanic(f func()) (has bool, err error) {
	defer func() {
		var report any
		if report = recover(); report != nil {
			has = true
			err = fmt.Errorf("%v", report)
		}
	}()

	f()

	return has, err
}

// expectPanic executes the function f with the expectation to recover from a panic. If no panic occurred or if the
// panic message is not the one expected, ExpectPanic returns (false, error).
func expectPanic(expectedError error, f func()) (bool, error) {
	hasPanic, err := hasPanic(f)

	if !hasPanic {
		return false, errNoPanic
	}

	if expectedError == nil {
		return true, nil
	}

	if err == nil {
		return false, errNoPanicMessage
	}

	if err.Error() != expectedError.Error() {
		return false, fmt.Errorf("expected %q, got: %w", expectedError, err)
	}

	return true, nil
}

type i2ospTest struct {
	encoded []byte
	value   int
	size    int
}

var I2OSPVectors = []i2ospTest{
	{
		[]byte{0}, 0, 1,
	},
	{
		[]byte{1}, 1, 1,
	},
	{
		[]byte{0xff}, 255, 1,
	},
	{
		[]byte{0x01, 0x00}, 256, 2,
	},
	{
		[]byte{0xff, 0xff}, 65535, 2,
	},
	{
		[]byte{0xff, 0xe3, 0xd0}, 16770000, 3,
	},
	{
		[]byte{0xff, 0xff, 0xe3, 0x80}, 4294960000, 4,
	},
}

func TestI2osp(t *testing.T) {
	for i, v := range I2OSPVectors {
		t.Run(fmt.Sprintf("%d - %d - %v", v.value, v.size, v.encoded), func(t *testing.T) {
			r := i2osp(v.value, v.size)

			if !bytes.Equal(r, v.encoded) {
				t.Fatalf(
					"invalid encoding for %d. Expected '%s', got '%v'",
					i,
					hex.EncodeToString(v.encoded),
					hex.EncodeToString(r),
				)
			}
		})
	}

	length := -1
	if hasPanic, err := expectPanic(nil, func() {
		_ = i2osp(1, length)
	}); !hasPanic {
		t.Fatalf("expected panic with with negative length: %v", err)
	}

	length = 0
	if hasPanic, err := expectPanic(nil, func() {
		_ = i2osp(1, length)
	}); !hasPanic {
		t.Fatalf("expected panic with with 0 length: %v", err)
	}

	length = 5
	if hasPanic, err := expectPanic(nil, func() {
		_ = i2osp(1, length)
	}); !hasPanic {
		t.Fatalf("expected panic with length too big: %v", err)
	}

	negative := -1
	if hasPanic, err := expectPanic(nil, func() {
		_ = i2osp(negative, 4)
	}); !hasPanic {
		t.Fatalf("expected panic with negative input: %v", err)
	}

	tooLarge := 1 << 32
	length = 1
	if hasPanic, err := expectPanic(nil, func() {
		_ = i2osp(tooLarge, length)
	}); !hasPanic {
		t.Fatalf("expected panic with exceeding value for the length: %v", err)
	}

	lengths := map[int]int{
		100:           1,
		1 << 8:        2,
		1 << 16:       3,
		(1 << 32) - 1: 4,
	}

	for k, v := range lengths {
		r := i2osp(k, v)

		if len(r) != v {
			t.Fatalf("invalid length for %d. Expected '%d', got '%d' (%v)", k, v, len(r), r)
		}
	}
}
