/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2014, 2015, 2016 by Axel Kenzo, axelkenzo@mail.ru                               */
/*   All rights reserved.                                                                          */
/*                                                                                                 */
/*   Redistribution and use in source and binary forms, with or without modification, are          */
/*   permitted provided that the following conditions are met:                                     */
/*                                                                                                 */
/*   1. Redistributions of source code must retain the above copyright notice, this list of        */
/*      conditions and the following disclaimer.                                                   */
/*   2. Redistributions in binary form must reproduce the above copyright notice, this list of     */
/*      conditions and the following disclaimer in the documentation and/or other materials        */
/*      provided with the distribution.                                                            */
/*   3. Neither the name of the copyright holder nor the names of its contributors may be used     */
/*      to endorse or promote products derived from this software without specific prior written   */
/*      permission.                                                                                */
/*                                                                                                 */
/*   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS   */
/*   OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF               */
/*   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL        */
/*   THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, */
/*   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE */
/*   GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED    */
/*   AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     */
/*   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED  */
/*   OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/*                                                                                                 */
/*   ak_sha.c                                                                                      */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_hash.h>

/* ----------------------------------------------------------------------------------------------- */
/*                                            sha256                                               */
/* ----------------------------------------------------------------------------------------------- */
 #define Ch(x,y,z)       (z ^ (x & (y ^ z)))
 #define Maj(x,y,z)      (((x | y) & z) | (x & y))
 #define S(x, n)         rotrFixed(x, n)
 #define R(x, n)         (((x)&0xFFFFFFFFL)>>(n))
 #define Sigma0(x)       (S(x, 2) ^ S(x, 13) ^ S(x, 22))
 #define Sigma1(x)       (S(x, 6) ^ S(x, 11) ^ S(x, 25))
 #define Gamma0(x)       (S(x, 7) ^ S(x, 18) ^ R(x, 3))
 #define Gamma1(x)       (S(x, 17) ^ S(x, 19) ^ R(x, 10))

 #define RND(a,b,c,d,e,f,g,h,i) \
     t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i]; \
     t1 = Sigma0(a) + Maj(a, b, c); \
     d += t0; \
     h  = t0 + t1;

/* ----------------------------------------------------------------------------------------------- */
 static inline ak_uint32 rotrFixed( const ak_uint32 x, const ak_uint32 y)
{
        return (x >> y) | (x << (sizeof(y) * 8 - y));
}

/* ----------------------------------------------------------------------------------------------- */
 static inline ak_uint32 rotlFixed( ak_uint32 x, ak_uint32 y )
{
        return (x << y) | (x >> (sizeof(y) * 8 - y));
}

/* ----------------------------------------------------------------------------------------------- */
 static inline ak_uint64 rotlFixed64( ak_uint64 x, ak_uint64 y )
{
        return (x << y) | (x >> (sizeof(y) * 8 - y));
}

/* ----------------------------------------------------------------------------------------------- */
 static inline ak_uint64 rotrFixed64( ak_uint64 x, ak_uint64 y )
{
        return (x >> y) | (x << (sizeof(y) * 8 - y));
}

/* ----------------------------------------------------------------------------------------------- */
 static inline ak_uint32 ByteReverseWord32( ak_uint32 value )
{
        return rotlFixed(((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8), 16U );
}

/* ----------------------------------------------------------------------------------------------- */
 static inline void ByteReverseWords( ak_uint32 *out, const ak_uint32* in, ak_uint32 byteCount )
{
    ak_uint32 idx = 0;
    ak_uint32 count = byteCount/sizeof( ak_uint32 );
    for( idx = 0; idx < count; idx++ ) out[idx] = ByteReverseWord32( in[idx] );
}

/* ----------------------------------------------------------------------------------------------- */
 static inline void ByteReverseBytes( void *out, const void *in, ak_uint32 byteCount )
{
    ByteReverseWords( ( ak_uint32 *)out, (const ak_uint32*)in, byteCount );
}

/* ----------------------------------------------------------------------------------------------- */
 static inline ak_uint64 ByteReverseWord64( ak_uint64 value )
{
        value = ((value & 0xFF00FF00FF00FF00) >> 8) |
            ((value & 0x00FF00FF00FF00FF) << 8);
        value = ((value & 0xFFFF0000FFFF0000) >> 16) |
            ((value & 0x0000FFFF0000FFFF) << 16);
        return rotlFixed64( value, 32U );
}

/* ----------------------------------------------------------------------------------------------- */
 static inline void ByteReverseWords64( ak_uint64* out, const ak_uint64* in, ak_uint32 byteCount )
{
    ak_uint32 idx = 0;
    ak_uint32 count = byteCount/sizeof( ak_uint64 );

    for( idx = 0; idx < count; idx++ ) out[idx] = ByteReverseWord64(in[idx]);
}
/* ----------------------------------------------------------------------------------------------- */

/* ----------------------------------------------------------------------------------------------- */
 static const ak_uint32 K[64] = {
    0x428A2F98L, 0x71374491L, 0xB5C0FBCFL, 0xE9B5DBA5L, 0x3956C25BL,
    0x59F111F1L, 0x923F82A4L, 0xAB1C5ED5L, 0xD807AA98L, 0x12835B01L,
    0x243185BEL, 0x550C7DC3L, 0x72BE5D74L, 0x80DEB1FEL, 0x9BDC06A7L,
    0xC19BF174L, 0xE49B69C1L, 0xEFBE4786L, 0x0FC19DC6L, 0x240CA1CCL,
    0x2DE92C6FL, 0x4A7484AAL, 0x5CB0A9DCL, 0x76F988DAL, 0x983E5152L,
    0xA831C66DL, 0xB00327C8L, 0xBF597FC7L, 0xC6E00BF3L, 0xD5A79147L,
    0x06CA6351L, 0x14292967L, 0x27B70A85L, 0x2E1B2138L, 0x4D2C6DFCL,
    0x53380D13L, 0x650A7354L, 0x766A0ABBL, 0x81C2C92EL, 0x92722C85L,
    0xA2BFE8A1L, 0xA81A664BL, 0xC24B8B70L, 0xC76C51A3L, 0xD192E819L,
    0xD6990624L, 0xF40E3585L, 0x106AA070L, 0x19A4C116L, 0x1E376C08L,
    0x2748774CL, 0x34B0BCB5L, 0x391C0CB3L, 0x4ED8AA4AL, 0x5B9CCA4FL,
    0x682E6FF3L, 0x748F82EEL, 0x78A5636FL, 0x84C87814L, 0x8CC70208L,
    0x90BEFFFAL, 0xA4506CEBL, 0xBEF9A3F7L, 0xC67178F2L
};

/* ----------------------------------------------------------------------------------------------- */
 #define SHA256                 2   /* hash type unique */
 #define SHA256_BLOCK_SIZE     64
 #define SHA256_DIGEST_SIZE    32
 #define SHA256_PAD_SIZE       56

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура для хранения внутренних данных контекста функции хеширования SHA256           */
 struct sha256_ctx {
    ak_uint32  buffLen;   /* in bytes          */
    ak_uint32  loLen;     /* length in bytes   */
    ak_uint32  hiLen;     /* length in bytes   */
    ak_uint32  digest[SHA256_DIGEST_SIZE / sizeof( ak_uint32 )];
    ak_uint32  buffer[SHA256_BLOCK_SIZE  / sizeof( ak_uint32 )];
};

/* ----------------------------------------------------------------------------------------------- */
 static void Transform( struct sha256_ctx *ctx )
{
     ak_uint32 S[8], W[64], t0, t1;

     /* Copy context->state[] to working vars */
     int i = 0;
     for( i = 0; i < 8; i++ ) S[i] = ctx->digest[i];
     for( i = 0; i < 16; i++ ) W[i] = ctx->buffer[i];
     for( i = 16; i < 64; i++ )
           W[i] = Gamma1(W[i-2]) + W[i-7] + Gamma0(W[i-15]) + W[i-16];
     for( i = 0; i < 64; i += 8 ) {
      RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],i+0);
      RND(S[7],S[0],S[1],S[2],S[3],S[4],S[5],S[6],i+1);
      RND(S[6],S[7],S[0],S[1],S[2],S[3],S[4],S[5],i+2);
      RND(S[5],S[6],S[7],S[0],S[1],S[2],S[3],S[4],i+3);
      RND(S[4],S[5],S[6],S[7],S[0],S[1],S[2],S[3],i+4);
      RND(S[3],S[4],S[5],S[6],S[7],S[0],S[1],S[2],i+5);
      RND(S[2],S[3],S[4],S[5],S[6],S[7],S[0],S[1],i+6);
      RND(S[1],S[2],S[3],S[4],S[5],S[6],S[7],S[0],i+7);
     }
     /* Add the working vars back into digest state[] */
     for( i = 0; i < 8; i++ ) ctx->digest[i] += S[i];
}

/* ----------------------------------------------------------------------------------------------- */
 static void AddLength( struct sha256_ctx *ctx, const ak_uint32 len )
{
       ak_uint32 tmp = ctx->loLen;
       if ( (ctx->loLen += len ) < tmp ) ctx->hiLen++;  /* carry low to high */
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Очистка внутреннего состояния контекста                                                 */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_hash_sha256_clean( ak_hash ctx )
{
     struct sha256_ctx *sx = NULL;
     if( ctx == NULL ) {
       ak_error_message( ak_error_null_pointer, "using null pointer to a context", __func__ );
       return;
     }
     sx = ( struct sha256_ctx * ) ctx->data;
     sx->digest[0] = 0x6A09E667L;
     sx->digest[1] = 0xBB67AE85L;
     sx->digest[2] = 0x3C6EF372L;
     sx->digest[3] = 0xA54FF53AL;
     sx->digest[4] = 0x510E527FL;
     sx->digest[5] = 0x9B05688CL;
     sx->digest[6] = 0x1F83D9ABL;
     sx->digest[7] = 0x5BE0CD19L;
     sx->buffLen = 0;
     sx->loLen   = 0;
     sx->hiLen   = 0;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция помещает в указанную область памяти текущее значение хеш-кода                   */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_hash_sha256_get_code( ak_hash ctx, ak_pointer out )
{
  struct sha256_ctx *sx = NULL;
  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, "using null pointer to a context", __func__ );
    return;
  }
  sx = ( struct sha256_ctx * ) ctx->data;
  memcpy( out, sx->digest, SHA256_DIGEST_SIZE );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция изменения (дополнения) внутреннего состояния контекста хеширования              */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_hash_sha256_update( ak_hash ctx, const ak_pointer in, const ak_uint64 size )
{
  ak_uint32 len = (ak_uint32) size;
  struct sha256_ctx *sx = NULL;
  ak_uint8 *local = NULL, *data = ( ak_uint8 *) in;

  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, "using null pointer to a context", __func__ );
    return;
  }

  /* do block size increments */
  sx = ( struct sha256_ctx * ) ctx->data;
  local = ( ak_uint8 *) sx->buffer;

  while (len) {
      ak_uint32 add = ak_min( len, SHA256_BLOCK_SIZE - sx->buffLen );
      memcpy( &local[sx->buffLen], data, add );

      sx->buffLen += add;
      data    += add;
      len     -= add;

      if ( sx->buffLen == SHA256_BLOCK_SIZE) {
          ByteReverseBytes( local, local, SHA256_BLOCK_SIZE ); /* только для little-endian */
          Transform(sx);
          AddLength( sx, SHA256_BLOCK_SIZE );
          sx->buffLen = 0;
      }
  }
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция завершения работы и закрытия контекста хеширования                              */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_hash_sha256_final( ak_hash ctx, const ak_pointer in, const ak_uint64 size )
{
   ak_uint8 *local = NULL;
   struct sha256_ctx *sx = NULL;

   if( ctx == NULL ) {
     ak_error_message( ak_error_null_pointer, "using null pointer to a context", __func__ );
     return;
   }
   if( size ) ak_hash_sha256_update( ctx, in, size );

   sx = ( struct sha256_ctx * ) ctx->data;
   local = ( ak_uint8* ) sx->buffer;

   AddLength( sx, sx->buffLen );  /* before adding pads */
   local[sx->buffLen++] = 0x80;  /* add 1 */

   /* pad with zeros */
   if (sx->buffLen > SHA256_PAD_SIZE) {
       memset(&local[sx->buffLen], 0, SHA256_BLOCK_SIZE - sx->buffLen);
       sx->buffLen += SHA256_BLOCK_SIZE - sx->buffLen;

       ByteReverseBytes( local, local, SHA256_BLOCK_SIZE );
       Transform(sx);
       sx->buffLen = 0;
   }
   memset( &local[sx->buffLen], 0, SHA256_PAD_SIZE - sx->buffLen);

   /* put lengths in bits */
   sx->hiLen = (sx->loLen >> (8*sizeof(sx->loLen) - 3)) + (sx->hiLen << 3);
   sx->loLen = sx->loLen << 3;

   /* store lengths */
   ByteReverseBytes( local, local, SHA256_BLOCK_SIZE );
   /* ! length ordering dependent on digest endian type ! */
   memcpy(&local[SHA256_PAD_SIZE], &sx->hiLen, sizeof( ak_uint32 ));
   memcpy(&local[SHA256_PAD_SIZE + sizeof(ak_uint32)], &sx->loLen,
                                                     sizeof(ak_uint32));
   Transform(sx);
   ByteReverseWords( sx->digest, sx->digest, SHA256_DIGEST_SIZE);
}

/* ----------------------------------------------------------------------------------------------- */
 ak_hash ak_hash_new_sha256( void )
{
  ak_hash ctx = ak_hash_new( sizeof( struct sha256_ctx ));
  if( ctx == NULL ) {
    ak_error_message( ak_error_create_function, "incorrect context creation", __func__ );
    return NULL;
  }
  ctx->bsize = SHA256_BLOCK_SIZE;
  ctx->hsize = SHA256_DIGEST_SIZE; /* длина хешкода составляет 256 бит */

  if(( ctx->oid = ak_oids_find_by_name( "sha2-256" )) == NULL ) {
    ak_error_message( ak_error_find_pointer, "incorrect search of sha256 OID", __func__ );
    return ctx = ak_hash_delete( ctx );
  }
  /* устанавливаем функции - обработчики событий */
  ctx->clean =  ak_hash_sha256_clean;
  ctx->code =   ak_hash_sha256_get_code;
  ctx->update = ak_hash_sha256_update;
  ctx->final =  ak_hash_sha256_final;
 return ctx;
}

/* ----------------------------------------------------------------------------------------------- */
 #define SHA512                 4   /* hash type unique */
 #define SHA512_BLOCK_SIZE    128
 #define SHA512_DIGEST_SIZE    64
 #define  SHA512_PAD_SIZE     112

/* ----------------------------------------------------------------------------------------------- */
/*                                            sha512                                               */
/* ----------------------------------------------------------------------------------------------- */
 #define blk0(i) (W[i] = ctx->buffer[i])
 #define blk2(i) (W[i&15]+=s1(W[(i-2)&15])+W[(i-7)&15]+s0(W[(i-15)&15]))

 #define a(i) T[(0-i)&7]
 #define b(i) T[(1-i)&7]
 #define c(i) T[(2-i)&7]
 #define d(i) T[(3-i)&7]
 #define e(i) T[(4-i)&7]
 #define f(i) T[(5-i)&7]
 #define g(i) T[(6-i)&7]
 #define h(i) T[(7-i)&7]

 #define S0(x) (rotrFixed64(x,28)^rotrFixed64(x,34)^rotrFixed64(x,39))
 #define S1(x) (rotrFixed64(x,14)^rotrFixed64(x,18)^rotrFixed64(x,41))
 #define s0(x) (rotrFixed64(x,1)^rotrFixed64(x,8)^(x>>7))
 #define s1(x) (rotrFixed64(x,19)^rotrFixed64(x,61)^(x>>6))

 #define R64(i) h(i)+=S1(e(i))+Ch(e(i),f(i),g(i))+K[i+j]+(j?blk2(i):blk0(i));\
        d(i)+=h(i);h(i)+=S0(a(i))+Maj(a(i),b(i),c(i))

/* ----------------------------------------------------------------------------------------------- */
 static const ak_uint64 K512[80] = {
        0x428a2f98d728ae22, 0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019,
        0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe,
        0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
        0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210,
        0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725,
        0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001,
        0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910,
        0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
        0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60,
        0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9,
        0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6,
        0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура для хранения внутренних данных контекста функции хеширования SHA512           */
 struct sha512_ctx
{
     ak_uint32  buffLen;   /* in bytes          */
     ak_uint32  loLen;     /* length in bytes   */
     ak_uint32  hiLen;     /* length in bytes   */
     ak_uint64  digest[SHA512_DIGEST_SIZE / sizeof( ak_uint64 )];
     ak_uint64  buffer[SHA512_BLOCK_SIZE  / sizeof( ak_uint64 )];
};

/* ----------------------------------------------------------------------------------------------- */
 void Transform64( struct sha512_ctx *ctx )
{
      ak_uint32 j = 0;
      const ak_uint64* K = K512;
      ak_uint64 W[16], T[8];

     /* Copy digest to working vars */
      memcpy( T, ctx->digest, sizeof(T) );

     /* 64 operations, partially loop unrolled */
      for( j = 0; j < 80; j += 16 ) {
         R64( 0); R64( 1); R64( 2); R64( 3);
         R64( 4); R64( 5); R64( 6); R64( 7);
         R64( 8); R64( 9); R64(10); R64(11);
         R64(12); R64(13); R64(14); R64(15);
      }

     /* Add the working vars back into digest */
      ctx->digest[0] += a(0);
      ctx->digest[1] += b(0);
      ctx->digest[2] += c(0);
      ctx->digest[3] += d(0);
      ctx->digest[4] += e(0);
      ctx->digest[5] += f(0);
      ctx->digest[6] += g(0);
      ctx->digest[7] += h(0);

     /* Wipe variables */
      memset( W, 0, sizeof(W) ); memset( T, 0, sizeof(T) );
}

/* ----------------------------------------------------------------------------------------------- */
 void AddLength64( struct sha512_ctx *ctx, ak_uint32 len )
{
       ak_uint32 tmp = ctx->loLen;
       if (( ctx->loLen += len) < tmp) ctx->hiLen++; /* carry low to high */
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Очистка внутреннего состояния контекста                                                 */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_hash_sha512_clean( ak_hash ctx )
{
     struct sha512_ctx *sx = NULL;
     if( ctx == NULL ) {
       ak_error_message( ak_error_null_pointer, "using null pointer to a context", __func__ );
       return;
     }
     sx = ( struct sha512_ctx * ) ctx->data;
     sx->digest[0] = 0x6a09e667f3bcc908;
     sx->digest[1] = 0xbb67ae8584caa73b;
     sx->digest[2] = 0x3c6ef372fe94f82b;
     sx->digest[3] = 0xa54ff53a5f1d36f1;
     sx->digest[4] = 0x510e527fade682d1;
     sx->digest[5] = 0x9b05688c2b3e6c1f;
     sx->digest[6] = 0x1f83d9abfb41bd6b;
     sx->digest[7] = 0x5be0cd19137e2179;

     sx->buffLen = 0;
     sx->loLen   = 0;
     sx->hiLen   = 0;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция помещает в указанную область памяти текущее значение хеш-кода                   */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_hash_sha512_get_code( ak_hash ctx, ak_pointer out )
{
  struct sha512_ctx *sx = NULL;
  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, "using null pointer to a context", __func__ );
    return;
  }
  sx = ( struct sha512_ctx * ) ctx->data;
  memcpy( out, sx->digest, SHA512_DIGEST_SIZE );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция изменения (дополнения) внутреннего состояния контекста хеширования              */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_hash_sha512_update( ak_hash ctx, const ak_pointer in, const ak_uint64 size )
{
  ak_uint32 len = (ak_uint32) size;
  struct sha512_ctx *sx = NULL;
  ak_uint8 *local = NULL, *data = ( ak_uint8 *) in;

  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, "using null pointer to a context", __func__ );
    return;
  }

  /* do block size increments */
  sx = ( struct sha512_ctx * ) ctx->data;
  local = ( ak_uint8 *) sx->buffer;

    while (len) {
        ak_uint32 add = ak_min( len, SHA512_BLOCK_SIZE - sx->buffLen);
        memcpy( &local[sx->buffLen], data, add );

        sx->buffLen += add;
        data    += add;
        len     -= add;

        if ( sx->buffLen == SHA512_BLOCK_SIZE ) {
            ByteReverseWords64( sx->buffer, sx->buffer, SHA512_BLOCK_SIZE);
            Transform64( sx );
            AddLength64( sx, SHA512_BLOCK_SIZE );
            sx->buffLen = 0;
        }
    }
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция завершения работы и закрытия контекста хеширования                              */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_hash_sha512_final( ak_hash ctx, const ak_pointer in, const ak_uint64 size )
{
   ak_uint8 *local = NULL;
   struct sha512_ctx *sx = NULL;
   ak_uint64 xlen = 0;

   if( ctx == NULL ) {
     ak_error_message( ak_error_null_pointer, "using null pointer to a context", __func__ );
     return;
   }
   if( size ) ak_hash_sha512_update( ctx, in, size );

   sx = ( struct sha512_ctx * ) ctx->data;
   local = ( ak_uint8* ) sx->buffer;

     AddLength64( sx, sx->buffLen );   /* before adding pads */
     local[sx->buffLen++] = 0x80;  /* add 1 */

     /* pad with zeros */
     if ( sx->buffLen > SHA512_PAD_SIZE ) {
         memset( &local[sx->buffLen], 0, SHA512_BLOCK_SIZE - sx->buffLen );
         sx->buffLen += SHA512_BLOCK_SIZE - sx->buffLen;

         ByteReverseWords64( sx->buffer, sx->buffer, SHA512_BLOCK_SIZE );
         Transform64( sx );
         sx->buffLen = 0;
     }
     memset( &local[ sx->buffLen], 0, SHA512_PAD_SIZE - sx->buffLen );

     /* put lengths in bits */
     sx->hiLen = (sx->loLen >> 29) + (sx->hiLen << 3); sx->loLen = sx->loLen << 3;

     /* ak_uint64ch xlen;
     xlen.w[0] = loLen; xlen.w[1] = hiLen;
     */
     xlen = sx->hiLen;
     xlen <<= 32;
     xlen += sx->loLen;

     /* store lengths */
     ByteReverseWords64( sx->buffer, sx->buffer, SHA512_PAD_SIZE );
     /* ! length ordering dependent on digest endian type ! */
                                                              /* it's important changes! */
     sx->buffer[SHA512_BLOCK_SIZE / sizeof( ak_uint64 ) - 2] = 0; /* hiLen; */
     sx->buffer[SHA512_BLOCK_SIZE / sizeof( ak_uint64 ) - 1] = xlen; /* loLen; */

     Transform64( sx );
     ByteReverseWords64( sx->digest, sx->digest, SHA512_DIGEST_SIZE );
 }


/* ----------------------------------------------------------------------------------------------- */
 ak_hash ak_hash_new_sha512( void )
{
  ak_hash ctx = ak_hash_new( sizeof( struct sha512_ctx ));
  if( ctx == NULL ) {
    ak_error_message( ak_error_create_function, "incorrect context creation", __func__ );
    return NULL;
  }
  ctx->bsize = SHA512_BLOCK_SIZE;
  ctx->hsize = SHA512_DIGEST_SIZE; /* длина хешкода составляет 512 бит */

  if(( ctx->oid = ak_oids_find_by_name( "sha2-512" )) == NULL ) {
    ak_error_message( ak_error_find_pointer, "incorrect search of sha512 OID", __func__ );
    return ctx = ak_hash_delete( ctx );
  }
  /* устанавливаем функции - обработчики событий */
  ctx->clean =  ak_hash_sha512_clean;
  ctx->code =   ak_hash_sha512_get_code;
  ctx->update = ak_hash_sha512_update;
  ctx->final =  ak_hash_sha512_final;
 return ctx;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                  функции тестирования                                           */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Проверка корректной работы функции SHA-256
    @return Если тестирование прошло успешно возвращается ak_true (истина). В противном случае,
    возвращается ak_false.                                                                         */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_hash_test_sha256( void )
{
  ak_bool result = ak_true;
  char *str = NULL;
  ak_hash ctx = NULL;
  ak_buffer rbuff = NULL, hbuff = NULL;
  int audit = ak_log_get_level();
  ak_uint8 zin[1000000];

 /* создаем контекст функции хеширования */
  if((ctx = ak_hash_new_sha256( )) == NULL ) {
    ak_error_message( ak_error_get_value(), "wrong creation of hash function context", __func__ );
    result = ak_false;
    goto lab_exit;
  }

 /* пример 1 */
  result = ak_buffer_is_equal(
    rbuff = ak_hash_data( ctx, "abc", 3, NULL ),
    hbuff =
        ak_buffer_new_hexstr( "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD" ));
  if( result != ak_true ) {
    ak_error_message( ak_error_not_equal_data, "the \"abc\" test is wrong", __func__ );
    ak_log_set_message(( str = ak_buffer_to_hexstr( hbuff ))); free( str );
    ak_log_set_message(( str = ak_buffer_to_hexstr( rbuff ))); free( str );
    goto lab_exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, "the \"abc\" test is Ok", __func__ );
  rbuff = ak_buffer_delete( rbuff );
  hbuff = ak_buffer_delete( hbuff );

 /* пример 2 */
  result = ak_buffer_is_equal(
    rbuff = ak_hash_data( ctx, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, NULL ),
    hbuff =
        ak_buffer_new_hexstr( "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1" ));
  if( result != ak_true ) {
    ak_error_message( ak_error_not_equal_data,
       "the \"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\" test is wrong", __func__ );
    ak_log_set_message(( str = ak_buffer_to_hexstr( hbuff ))); free( str );
    ak_log_set_message(( str = ak_buffer_to_hexstr( rbuff ))); free( str );
    goto lab_exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok,
          "the \"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\" test is Ok", __func__ );
  rbuff = ak_buffer_delete( rbuff );
  hbuff = ak_buffer_delete( hbuff );

 /* пример 3 */
  zin[0] = 0xbd;
  result = ak_buffer_is_equal(
    rbuff = ak_hash_data( ctx, zin, 1, NULL ),
    hbuff =
        ak_buffer_new_hexstr( "68325720AABD7C82F30F554B313D0570C95ACCBB7DC4B5AAE11204C08FFE732B" ));
  if( result != ak_true ) {
    ak_error_message( ak_error_not_equal_data, "the one byte test is wrong", __func__ );
    ak_log_set_message(( str = ak_buffer_to_hexstr( hbuff ))); free( str );
    ak_log_set_message(( str = ak_buffer_to_hexstr( rbuff ))); free( str );
    goto lab_exit;
  }
  if( audit >= ak_log_maximum )
                               ak_error_message( ak_error_ok, "the one byte test is Ok", __func__ );
  rbuff = ak_buffer_delete( rbuff );
  hbuff = ak_buffer_delete( hbuff );

 /* пример 4 */
  memset( zin, 0, 57 );
  result = ak_buffer_is_equal(
    rbuff = ak_hash_data( ctx, zin, 57, NULL ),
    hbuff =
        ak_buffer_new_hexstr( "65A16CB7861335D5ACE3C60718B5052E44660726DA4CD13BB745381B235A1785" ));
  if( result != ak_true ) {
     ak_error_message( ak_error_not_equal_data, "the 57 zero bytes test is wrong", __func__ );
     ak_log_set_message(( str = ak_buffer_to_hexstr( hbuff ))); free( str );
     ak_log_set_message(( str = ak_buffer_to_hexstr( rbuff ))); free( str );
     goto lab_exit;
  }
  if( audit >= ak_log_maximum )
                          ak_error_message( ak_error_ok, "the 57 zero bytes test is Ok", __func__ );
  rbuff = ak_buffer_delete( rbuff );
  hbuff = ak_buffer_delete( hbuff );

 /* пример 5 */
  memset( zin, 0x41, 1000 );
  result = ak_buffer_is_equal(
    rbuff = ak_hash_data( ctx, zin, 1000, NULL ),
    hbuff =
        ak_buffer_new_hexstr( "C2E686823489CED2017F6059B8B239318B6364F6DCD835D0A519105A1EADD6E4" ));
  if( result != ak_true ) {
    ak_error_message( ak_error_not_equal_data, "the 1000 fixed bytes test is wrong", __func__ );
    ak_log_set_message(( str = ak_buffer_to_hexstr( hbuff ))); free( str );
    ak_log_set_message(( str = ak_buffer_to_hexstr( rbuff ))); free( str );
    goto lab_exit;
  }
  if( audit >= ak_log_maximum )
                       ak_error_message( ak_error_ok, "the 1000 fixed bytes test is Ok", __func__ );
  rbuff = ak_buffer_delete( rbuff );
  hbuff = ak_buffer_delete( hbuff );

 /* пример 6 */
  memset( zin, 0, 1000000 );
  result = ak_buffer_is_equal(
    rbuff = ak_hash_data( ctx, zin, 1000000, NULL ),
    hbuff =
        ak_buffer_new_hexstr( "D29751F2649B32FF572B5E0A9F541EA660A50F94FF0BEEDFB0B692B924CC8025" ));
  if( result != ak_true ) {
    ak_error_message( ak_error_not_equal_data, "the billion zeroes test is wrong", __func__ );
    ak_log_set_message(( str = ak_buffer_to_hexstr( hbuff ))); free( str );
    ak_log_set_message(( str = ak_buffer_to_hexstr( rbuff ))); free( str );
    goto lab_exit;
  }
  if( audit >= ak_log_maximum )
                         ak_error_message( ak_error_ok, "the billion zeroes test is Ok", __func__ );
  rbuff = ak_buffer_delete( rbuff );
  hbuff = ak_buffer_delete( hbuff );

 /* хеширование пустого вектора */
  result = ak_buffer_is_equal(
    rbuff = ak_hash_data( ctx, "", 0, NULL ),
    hbuff =
        ak_buffer_new_hexstr( "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855" ));
  if( result != ak_true ) {
    ak_error_message( ak_error_not_equal_data, "the zero length vector test is wrong", __func__ );
    ak_log_set_message(( str = ak_buffer_to_hexstr( hbuff ))); free( str );
    ak_log_set_message(( str = ak_buffer_to_hexstr( rbuff ))); free( str );
    goto lab_exit;
  }
  if( audit >= ak_log_maximum )
                     ak_error_message( ak_error_ok, "the zero length vector test is Ok", __func__ );
 lab_exit:
  ctx = ak_hash_delete( ctx );
  rbuff = ak_buffer_delete( rbuff );
  hbuff = ak_buffer_delete( hbuff );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Проверка корректной работы функции SHA-512
    @return Если тестирование прошло успешно возвращается ak_true (истина). В противном случае,
    возвращается ak_false.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_hash_test_sha512( void )
{
  ak_bool result = ak_true;
  char *str = NULL;
  ak_hash ctx = NULL;
  ak_buffer rbuff = NULL, hbuff = NULL;
  int audit = ak_log_get_level();
  ak_uint8 zin[1000000];

 /* создаем контекст функции хеширования */
  if((ctx = ak_hash_new_sha512( )) == NULL ) {
    ak_error_message( ak_error_get_value(), "wrong creation of hash function context", __func__ );
    result = ak_false;
    goto lab_exit;
  }

 /* пример 1 */
  result = ak_buffer_is_equal(
    rbuff = ak_hash_data( ctx, "abc", 3, NULL ),
    hbuff =
      ak_buffer_new_hexstr( "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F" ));
  if( result != ak_true ) {
    ak_error_message( ak_error_not_equal_data, "the \"abc\" test is wrong", __func__ );
    ak_log_set_message(( str = ak_buffer_to_hexstr( hbuff ))); free( str );
    ak_log_set_message(( str = ak_buffer_to_hexstr( rbuff ))); free( str );
    goto lab_exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, "the \"abc\" test is Ok", __func__ );
  rbuff = ak_buffer_delete( rbuff );
  hbuff = ak_buffer_delete( hbuff );

 /* пример 2 */
  result = ak_buffer_is_equal(
    rbuff = ak_hash_data( ctx, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112, NULL ),
    hbuff =
        ak_buffer_new_hexstr( "8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909" ));
  if( result != ak_true ) {
    ak_error_message( ak_error_not_equal_data,
                                             "the 112 bytes long message test is wrong", __func__ );
    ak_log_set_message(( str = ak_buffer_to_hexstr( hbuff ))); free( str );
    ak_log_set_message(( str = ak_buffer_to_hexstr( rbuff ))); free( str );
    goto lab_exit;
  }
  if( audit >= ak_log_maximum )
                 ak_error_message( ak_error_ok, "the 112 bytes long message test is Ok", __func__ );
  rbuff = ak_buffer_delete( rbuff );
  hbuff = ak_buffer_delete( hbuff );

 /* пример 3 */
  memset( zin, 0x41, 1000 );
  result = ak_buffer_is_equal(
    rbuff = ak_hash_data( ctx, zin, 1000, NULL ),
    hbuff =
        ak_buffer_new_hexstr( "329C52AC62D1FE731151F2B895A00475445EF74F50B979C6F7BB7CAE349328C1D4CB4F7261A0AB43F936A24B000651D4A824FCDD577F211AEF8F806B16AFE8AF" ));
  if( result != ak_true ) {
    ak_error_message( ak_error_not_equal_data,
                                           "the 1000 fixed bytes message test is wrong", __func__ );
    ak_log_set_message(( str = ak_buffer_to_hexstr( hbuff ))); free( str );
    ak_log_set_message(( str = ak_buffer_to_hexstr( rbuff ))); free( str );
    goto lab_exit;
  }
  if( audit >= ak_log_maximum )
               ak_error_message( ak_error_ok, "the 1000 fixed bytes message test is Ok", __func__ );
  rbuff = ak_buffer_delete( rbuff );
  hbuff = ak_buffer_delete( hbuff );

 /* пример 4 */
  memset( zin, 0, 1000000 );
  result = ak_buffer_is_equal(
    rbuff = ak_hash_data( ctx, zin, 1000000, NULL ),
    hbuff =
        ak_buffer_new_hexstr( "CE044BC9FD43269D5BBC946CBEBC3BB711341115CC4ABDF2EDBC3FF2C57AD4B15DEB699BDA257FEA5AEF9C6E55FCF4CF9DC25A8C3CE25F2EFE90908379BFF7ED" ));
  if( result != ak_true ) {
    ak_error_message( ak_error_not_equal_data, "the billion zeroes message test is wrong", __func__ );
    ak_log_set_message(( str = ak_buffer_to_hexstr( hbuff ))); free( str );
    ak_log_set_message(( str = ak_buffer_to_hexstr( rbuff ))); free( str );
    goto lab_exit;
  }
  if( audit >= ak_log_maximum )
                 ak_error_message( ak_error_ok, "the billion zeroes message test is Ok", __func__ );
  rbuff = ak_buffer_delete( rbuff );
  hbuff = ak_buffer_delete( hbuff );

 /* хеширование пустого вектора */
  result = ak_buffer_is_equal(
    rbuff = ak_hash_data( ctx, "", 0, NULL ),
    hbuff =
        ak_buffer_new_hexstr( "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E" ));
  if( result != ak_true ) {
    ak_error_message( ak_error_not_equal_data, "the zero length vector test is wrong", __func__ );
    ak_log_set_message(( str = ak_buffer_to_hexstr( hbuff ))); free( str );
    ak_log_set_message(( str = ak_buffer_to_hexstr( rbuff ))); free( str );
    goto lab_exit;
  }
  if( audit >= ak_log_maximum )
                     ak_error_message( ak_error_ok, "the zero length vector test is Ok", __func__ );
 lab_exit:
  ctx = ak_hash_delete( ctx );
  rbuff = ak_buffer_delete( rbuff );
  hbuff = ak_buffer_delete( hbuff );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_sha.c  */
/* ----------------------------------------------------------------------------------------------- */
