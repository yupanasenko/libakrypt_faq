# Libakrypt

Libakrypt is a free and open source library (crypto module) for OpenSKZI project
distributed under the MIT License. This library written in C11 and provides some
interfaces for key management, data encryption, integrity checking, signing messages
and verifying of digital signatures. The main goal of Libakrypt
is implementation of many Russian crypto mechanisms, decribed by national
standards and methodological recomendations in accordance with R 1323565.1.012-2017
"Basic principles of creating and modernization for crypto modules".

We have implementation of:

1. GOST R 34.12-2015 block ciphers "Magma" & "Kuznechik" with 64 bit and 128 bit block sizes respectively;
2. GOST R 34.13-2015 modes for block ciphers;
3. new MGM mode (Multilinear Galois mode) for authenticated encryption;
4. GOST R 34.11-2012 & GOST R 34.11-94 hash functions;
5. Montgomery arithmetic for prime fileds and group operations on elliptic curves in short Weierstrass form;
6. GOST R 34.10-2012 digital signature algorithms for elliptic curves described by R 50.1.114-2016;
7. R 50.1.113-2016 crypto algorithms such as HMAC;
8. national variant of password-based key derivation function (PBKDF2) described by R 50.1.111-2016;
9. a some set of pseudo random generators for various operation systems including
   R 1323565.1.006-2017 mechanism.

Library can be used successfully under Linux, Windows (since XP), FreeBSD, MacOs and ReactOS operation systems.
Also we have positive runs of library on mobile devices under Sailfish OS 


## Compilation

The library can be compiled with many compilers,
such as gcc, clang, Microsoft Visual C, TinyCC and icc.
You can get the last version of source codes from github.com

    git clone https://github.com/axelkenzo/libakrypt-0.x

The build system for libakrypt is [cmake](https://cmake.org/).

### Unix
On Unix platforms you can compile & build library with following commands

    mkdir build
    cd build
    cmake ../libakrypt-0.x
    make

### Windows
On Windows you need to install [phtreads library](https://sourceware.org/pthreads-win32/).
After this you can run a Microsoft Visual 20XX Console and execute a following sequence

    mkdir build
    cd build
    cmake.exe -G "NMake Makefiles" ../libakrypt-0.x
    nmake.exe

The full list of compile & build options you can find
in documentation, see `doc` directory or libakrypt-doc-0.x.pdf (in russian).

## Attention

Since this version still under development we don't recomended to use it
in real security applications.

