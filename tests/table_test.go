// SPDX-License-Group: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package hash2curve_test

import "testing"

var (
	testHashToGroupInput = []byte("input data")
	testHashToGroupDST   = []byte("domain separation tag")
)

func testAll(t *testing.T, f func(*testHashToCurve)) {
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f(test)
		})
	}
}

type testHashToCurve struct {
	name         string
	hashToScalar string
	hashToGroup  string
	input        []byte
	dst          []byte
}

var tests = []*testHashToCurve{
	{
		name:         "Ristretto255",
		input:        testHashToGroupInput,
		dst:          testHashToGroupDST,
		hashToScalar: "7cf9410111022202c71f9d317d6fcd711a84fee5a406063f8376379bbe8a3f03",
		hashToGroup:  "d0f15a907366d66998784ff0148356bb0de24088680fb29d5fbe1a629d743b10",
	},
	{
		name:         "P256",
		input:        testHashToGroupInput,
		dst:          testHashToGroupDST,
		hashToScalar: "4b51fd1148439c3a30539e87a2a75c63d72f71b74d108184beeb933d259456b9",
		hashToGroup:  "03536d17bf54e34ebc3926d425e76502b54bc2c393369fc6df0c729a18df667f4c",
	},
	{
		name:         "P384",
		input:        testHashToGroupInput,
		dst:          testHashToGroupDST,
		hashToScalar: "d22b5352caa675f8a2f385236b95cbc1f84b9e34540b3587d6d55bd5032bf51aeb54ccab701c6f05a489b82ec301012d",
		hashToGroup:  "02777ff137e17b48ab4984de510461af79cf34609ac27f98eb2a4a553f94dbf31bf97b5cf7bac08f60bb8c7ee474a26202",
	},
	{
		name:         "P521",
		input:        testHashToGroupInput,
		dst:          testHashToGroupDST,
		hashToScalar: "01f4e5806586dbebd01e85b17da1eb2df4ac678bc8683b9baa5dd5fba6a0f9d1ff5621ed342a90273150fd095c7abc07f97d202183ec804d063b9fcc0b95daec0614",
		hashToGroup:  "0300d24ae26cefe28681d4cf35cf7bea7de3acd15f38ba0b835303c9cdc641d1912566041cb5f6939ad43f0b21e506cecc4a8124a0517dce94f2f1affa47f052f25bf0",
	},
	{
		name:         "Edwards25519",
		input:        testHashToGroupInput,
		dst:          testHashToGroupDST,
		hashToScalar: "90249f56fa61b29fc09b8787d9954a6beba6ca49e25c80f78560ca5458e5b807",
		hashToGroup:  "a2ca6693cdda5b8d204a506fe873ce1d3e58d5b14d04635e13c10ba9d5637f8f",
	},
	{
		name:         "secp256k1",
		input:        testHashToGroupInput,
		dst:          testHashToGroupDST,
		hashToScalar: "782a63d48eace435ac06468208d9a62e3680e4ddc3977c4345b2c6de08258b69",
		hashToGroup:  "0210dca4244e263298000ff1e9f0dfbf1c28333e1f0a252024e8b20b9921cdf3b2",
	},
}
