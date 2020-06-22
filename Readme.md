# Libakrypt: abstract

Libakrypt is a free and open source library (software crypto module) distributed under
the MIT License. This library written in C99 and provides some interfaces for
key management, data encryption, integrity checking, signing messages and verifying
of digital signatures. The main goal of Libakrypt is implementation a lot of Russian
crypto mechanisms, decribed by national standards and methodological recomendations
in accordance with R 1323565.1.012-2017
"Basic principles of creating and modernization for crypto modules".

We have implementation of:

 1. GOST R 34.12-2015 block ciphers "Magma" & "Kuznechik" with 64 bit and 128 bit block sizes respectively,
  see [here](https://datatracker.ietf.org/doc/draft-dolmatov-magma/) and [RFC 7801](https://tools.ietf.org/html/rfc7801);
 2. GOST R 34.13-2015 modes for block ciphers including CMAC algorithm;
 3. ACPKM encryption mode described by R 1323565.1.017-2018 and [RFC 8645](https://tools.ietf.org/html/rfc8645);
 4. Authenticated encryption mode (MGM, Multilinear Galois mode) described by R 1323565.026-2019,
 see also [here](https://datatracker.ietf.org/doc/draft-smyshlyaev-mgm/);
 5. GOST R 34.11-2012 hash functions from Streebog family, see [RFC-6986](https://tools.ietf.org/html/rfc6986);
 6. R 50.1.113-2016 crypto algorithms such as HMAC;
 7. Password-based key derivation function (PBKDF2) described by R 50.1.111-2016;
 8. A some set of pseudo random generators for various operation systems including R 1323565.1.006-2017 mechanism;
 9. Montgomery arithmetic for prime fileds;
10. Group operations on elliptic curves in short Weierstrass form for all elliptic curves
    described by R 1323565.024-2019;
11. GOST R 34.10-2012 digital signature generation and verification algorithms, see ISO/IEC 14888-3:2016;
12. x509 certificate management, including public keys formats described by R 1323565.023-2018.

The library can be compiled with many compilers,
such as `gcc`, `clang`, `Microsoft Visual C`, `TinyCC` and `icc`.
The build system is [cmake](https://cmake.org/).

Library can be used successfully under `Linux`, `Windows`, `FreeBSD` and `MacOS` operation systems.
Also we have positive runs on [ReactOS](https://reactos.org) and mobile devices under [Sailfish OS](https://sailfishos.org/).

We support various architectures such as `x86`, `x64`, `arm32v7`, `arm32v7eb`, `mips32r2` and `mips64r2`.

## Attention

Since this version still under development we don't recomended to use it
in real security applications.
