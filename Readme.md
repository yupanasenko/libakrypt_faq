Libakrypt
=========

Libakrypt is a free and open source library (crypto module) for OpenSKZI project.
This library written in C99 and provides some interfaces for
key management, data encryption, integrity checking, signing messages and
verifying of digital signatures. The main goal of Libakrypt
is implementation of many Russian crypto mechanisms, decribed by national
standards and methodological recomendations.

We have implementation of:
 - GOST R 34.12-2015 block ciphers "Magma" & "Kuznechik" with 64 bit and 128 bit
   block sizes respectively.
 - GOST R 34.13-2015 modes for block ciphers (including CMAC algorithm),
 - GOST R 34.11-2012 & GOST R 34.11-94 hash functions,
 - GOST R 34.10-2012 digital signature algorithms,
 - R 50.1.113-2016 crypto algorithms such as HMAC ,
 - a some set of pseudo random generators for various operation systems.

Compilation
-----------

This library can be compiled with many compilers,
such as gcc, clang, Microsoft Visual C, TinyCC.
You can get the last version of source codes from github.com

    git clone https://github.com/axelkenzo/libakrypt-0.x

After this you can compile & build library with following commands

    mkdir build
    cd build
    cmake ../libakrypt-0.x
    make

The full list of compile & build options you can find
in library's documentation, see libakrypt-doc-0.x.pdf (in russian).

Attention
-----------

Since this version still under development we don't recomended to use it
in real security applications.

