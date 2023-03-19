# YubiKey

[![Godoc][doc-image]][doc-url] [![Release][release-image]][release-url] [![Build][build-image]][build-url]

A Golang library that provides PIV smart card interface for YubiKey security keys.

## Usage

See [yubikey_test.go](yubikey_test.go), [slot_test.go](slot_test.go).

## Test

```shell
# Run tests
make test

# Continuous testing
make test-ui
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

## License

Licensed under The MIT License (MIT)  
For the full copyright and license information, please view the LICENSE.txt file.

[doc-url]: https://pkg.go.dev/github.com/devfacet/yubikey
[doc-image]: https://pkg.go.dev/badge/github.com/devfacet/yubikey

[release-url]: https://github.com/devfacet/yubikey/releases/latest
[release-image]: https://img.shields.io/github/release/devfacet/yubikey.svg?style=flat-square

[build-url]: https://github.com/devfacet/yubikey/actions/workflows/test.yaml
[build-image]: https://github.com/devfacet/yubikey/actions/workflows/test.yaml/badge.svg
