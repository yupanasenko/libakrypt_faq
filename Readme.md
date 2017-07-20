
Libakrypt
=========

Libakrypt is free and open source library (crypto module) for OpenSKZI project.
This library written in C99 and provides some interfaces for
key management, data encryption, integrity checking and
manipulation with digital signatures. The main goal of Libakrypt
is implementation of many Russian crypto mechanisms, decribed 
by national standards and methodical recomendations.
We have implementation of:
 - GOST R 34.12-2015 block ciphers "Magma" & "Kuznechik" with 64 bit and 128 bit block size соответственно.
 - GOST R 34.13-2015 modes for block ciphers (including a CMAC algorithm),
 - GOST G 34.11-2012 & GOST R 34.11-94 hash functions,
 - GOST R 34.10-2012 digital signature algorithms,
 - R 50.1.113-2016 algorithms such as HMAC and PBKDF,
 - a some set of random number generators for various operation systems.

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

The full list of variants to compile & build you can find
in library's documentation, see libakrypt-doc-0.x.pdf (in russian).

