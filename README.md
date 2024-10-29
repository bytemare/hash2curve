# Hash To Curve
[![hash2curve](https://github.com/bytemare/hash2curve/actions/workflows/code-scan.yml/badge.svg)](https://github.com/bytemare/hash2curve/actions/workflows/code-scan.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/hash2curve.svg)](https://pkg.go.dev/github.com/bytemare/hash2curve)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/bytemare/hash2curve/badge)](https://securityscorecards.dev/viewer/?uri=github.com/bytemare/hash2curve)
[![codecov](https://codecov.io/gh/bytemare/hash2curve/branch/main/graph/badge.svg?token=5bQfB0OctA)](https://codecov.io/gh/bytemare/hash2curve)

```
  import "github.com/bytemare/hash2curve"
```

Package hash2curve implements Hashing to Elliptic Curves as specified in [RFC 9380](https://datatracker.ietf.org/doc/rfc9380).

The following table shows supported groups with hash-to-curve capability and links each one to the underlying
implementations:

| Curve        | Backend                        |
|--------------|--------------------------------|
| Ristretto255 | github.com/gtank/ristretto255  |
| P-256        | filippo.io/nistec              |
| P-384        | filippo.io/nistec              |
| P-521        | filippo.io/nistec              |
| Edwards25519 | filippo.io/edwards25519        |
| Secp256k1    | github.com/bytemare/hash2curve |

#### What is hash2curve?

> Hashing to Elliptic Curves allows for encoding or hashing an arbitrary string to a point on an elliptic curve
> (or element in a group), therefore benefiting from interesting mathematical properties very useful in cryptographic
> protocols, like CPace, VOPRF, and OPAQUE.

#### References

## Documentation [![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/hash2curve.svg)](https://pkg.go.dev/github.com/bytemare/hash2curve)

You can find the documentation and usage examples in [the package doc](https://pkg.go.dev/github.com/bytemare/hash2curve) and [the project wiki](https://github.com/bytemare/hash2curve/wiki) .

## Versioning

[SemVer](http://semver.org) is used for versioning. For the versions available, see the [tags on the repository](https://github.com/bytemare/hash2curve/tags).


## Contributing

Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details on the code of conduct, and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
