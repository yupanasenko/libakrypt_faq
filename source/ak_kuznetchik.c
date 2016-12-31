/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2008 - 2016 by Axel Kenzo, axelkenzo@mail.ru                                    */
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
/*   ak_kuznetchik.c                                                                               */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_oid.h>
 #include <ak_skey.h>
 #include <ak_tools.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_BUILTIN_XOR_SI128
 #include <emmintrin.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Нелинейная перестановка алгоритма Кузнечик (ГОСТ Р 34.12-2015)                          */
 const static ak_uint8 pi[256] = {
   0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
   0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
   0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
   0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
   0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB, 0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
   0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
   0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
   0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
   0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
   0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
   0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
   0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
   0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
   0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE, 0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
   0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
   0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
 };

/* ---------------------------------------------------------------------------------------------- */
 const static ak_uint8 pinv[256] = {
   0xA5, 0x2D, 0x32, 0x8F, 0x0E, 0x30, 0x38, 0xC0, 0x54, 0xE6, 0x9E, 0x39, 0x55, 0x7E, 0x52, 0x91,
   0x64, 0x03, 0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18, 0x21, 0x72, 0xA8, 0xD1, 0x29, 0xC6, 0xA4, 0x3F,
   0xE0, 0x27, 0x8D, 0x0C, 0x82, 0xEA, 0xAE, 0xB4, 0x9A, 0x63, 0x49, 0xE5, 0x42, 0xE4, 0x15, 0xB7,
   0xC8, 0x06, 0x70, 0x9D, 0x41, 0x75, 0x19, 0xC9, 0xAA, 0xFC, 0x4D, 0xBF, 0x2A, 0x73, 0x84, 0xD5,
   0xC3, 0xAF, 0x2B, 0x86, 0xA7, 0xB1, 0xB2, 0x5B, 0x46, 0xD3, 0x9F, 0xFD, 0xD4, 0x0F, 0x9C, 0x2F,
   0x9B, 0x43, 0xEF, 0xD9, 0x79, 0xB6, 0x53, 0x7F, 0xC1, 0xF0, 0x23, 0xE7, 0x25, 0x5E, 0xB5, 0x1E,
   0xA2, 0xDF, 0xA6, 0xFE, 0xAC, 0x22, 0xF9, 0xE2, 0x4A, 0xBC, 0x35, 0xCA, 0xEE, 0x78, 0x05, 0x6B,
   0x51, 0xE1, 0x59, 0xA3, 0xF2, 0x71, 0x56, 0x11, 0x6A, 0x89, 0x94, 0x65, 0x8C, 0xBB, 0x77, 0x3C,
   0x7B, 0x28, 0xAB, 0xD2, 0x31, 0xDE, 0xC4, 0x5F, 0xCC, 0xCF, 0x76, 0x2C, 0xB8, 0xD8, 0x2E, 0x36,
   0xDB, 0x69, 0xB3, 0x14, 0x95, 0xBE, 0x62, 0xA1, 0x3B, 0x16, 0x66, 0xE9, 0x5C, 0x6C, 0x6D, 0xAD,
   0x37, 0x61, 0x4B, 0xB9, 0xE3, 0xBA, 0xF1, 0xA0, 0x85, 0x83, 0xDA, 0x47, 0xC5, 0xB0, 0x33, 0xFA,
   0x96, 0x6F, 0x6E, 0xC2, 0xF6, 0x50, 0xFF, 0x5D, 0xA9, 0x8E, 0x17, 0x1B, 0x97, 0x7D, 0xEC, 0x58,
   0xF7, 0x1F, 0xFB, 0x7C, 0x09, 0x0D, 0x7A, 0x67, 0x45, 0x87, 0xDC, 0xE8, 0x4F, 0x1D, 0x4E, 0x04,
   0xEB, 0xF8, 0xF3, 0x3E, 0x3D, 0xBD, 0x8A, 0x88, 0xDD, 0xCD, 0x0B, 0x13, 0x98, 0x02, 0x93, 0x80,
   0x90, 0xD0, 0x24, 0x34, 0xCB, 0xED, 0xF4, 0xCE, 0x99, 0x10, 0x44, 0x40, 0x92, 0x3A, 0x01, 0x26,
   0x12, 0x1A, 0x48, 0x68, 0xF5, 0x81, 0x8B, 0xC7, 0xD6, 0x20, 0x0A, 0x08, 0x00, 0x4C, 0xD7, 0x74
 };

/* ---------------------------------------------------------------------------------------------- */
 const static ak_uint8 L[16][16] = {
  { 0x01,0x94,0x20,0x85,0x10,0xC2,0xC0,0x01,0xFB,0x01,0xC0,0xC2,0x10,0x85,0x20,0x94 },
  { 0x94,0xA5,0x3C,0x44,0xD1,0x8D,0xB4,0x54,0xDE,0x6F,0x77,0x5D,0x96,0x74,0x2D,0x84 },
  { 0x84,0x64,0x48,0xDF,0xD3,0x31,0xA6,0x30,0xE0,0x5A,0x44,0x97,0xCA,0x75,0x99,0xDD },
  { 0xDD,0x0D,0xF8,0x52,0x91,0x64,0xFF,0x7B,0xAF,0x3D,0x94,0xF3,0xD9,0xD0,0xE9,0x10 },
  { 0x10,0x89,0x48,0x7F,0x91,0xEC,0x39,0xEF,0x10,0xBF,0x60,0xE9,0x30,0x5E,0x95,0xBD },
  { 0xBD,0xA2,0x48,0xC6,0xFE,0xEB,0x2F,0x84,0xC9,0xAD,0x7C,0x1A,0x68,0xBE,0x9F,0x27 },
  { 0x27,0x7F,0xC8,0x98,0xF3,0x0F,0x54,0x08,0xF6,0xEE,0x12,0x8D,0x2F,0xB8,0xD4,0x5D },
  { 0x5D,0x4B,0x8E,0x60,0x01,0x2A,0x6C,0x09,0x49,0xAB,0x8D,0xCB,0x14,0x87,0x49,0xB8 },
  { 0xB8,0x6E,0x2A,0xD4,0xB1,0x37,0xAF,0xD4,0xBE,0xF1,0x2E,0xBB,0x1A,0x4E,0xE6,0x7A },
  { 0x7A,0x16,0xF5,0x52,0x78,0x99,0xEB,0xD5,0xE7,0xC4,0x2D,0x06,0x17,0x62,0xD5,0x48 },
  { 0x48,0xC3,0x02,0x0E,0x58,0x90,0xE1,0xA3,0x6E,0xAF,0xBC,0xC5,0x0C,0xEC,0x76,0x6C },
  { 0x6C,0x4C,0xDD,0x65,0x01,0xC4,0xD4,0x8D,0xA4,0x02,0xEB,0x20,0xCA,0x6B,0xF2,0x72 },
  { 0x72,0xE8,0x14,0x07,0x49,0xF6,0xD7,0xA6,0x6A,0xD6,0x11,0x1C,0x0C,0x10,0x33,0x76 },
  { 0x76,0xE3,0x30,0x9F,0x6B,0x30,0x63,0xA1,0x2B,0x1C,0x43,0x68,0x70,0x87,0xC8,0xA2 },
  { 0xA2,0xD0,0x44,0x86,0x2D,0xB8,0x64,0xC1,0x9C,0x89,0x48,0x90,0xDA,0xC6,0x20,0x6E },
  { 0x6E,0x4D,0x8E,0xEA,0xA9,0xF6,0xBF,0x0A,0xF3,0xF2,0x8E,0x93,0xBF,0x74,0x98,0xCF }
};

/* ---------------------------------------------------------------------------------------------- */
 const static ak_uint8 Linv[16][16]  = {
 { 0xCF, 0x98, 0x74, 0xBF, 0x93, 0x8E, 0xF2, 0xF3, 0x0A, 0xBF, 0xF6, 0xA9, 0xEA, 0x8E, 0x4D, 0x6E },
 { 0x6E, 0x20, 0xC6, 0xDA, 0x90, 0x48, 0x89, 0x9C, 0xC1, 0x64, 0xB8, 0x2D, 0x86, 0x44, 0xD0, 0xA2 },
 { 0xA2, 0xC8, 0x87, 0x70, 0x68, 0x43, 0x1C, 0x2B, 0xA1, 0x63, 0x30, 0x6B, 0x9F, 0x30, 0xE3, 0x76 },
 { 0x76, 0x33, 0x10, 0x0C, 0x1C, 0x11, 0xD6, 0x6A, 0xA6, 0xD7, 0xF6, 0x49, 0x07, 0x14, 0xE8, 0x72 },
 { 0x72, 0xF2, 0x6B, 0xCA, 0x20, 0xEB, 0x02, 0xA4, 0x8D, 0xD4, 0xC4, 0x01, 0x65, 0xDD, 0x4C, 0x6C },
 { 0x6C, 0x76, 0xEC, 0x0C, 0xC5, 0xBC, 0xAF, 0x6E, 0xA3, 0xE1, 0x90, 0x58, 0x0E, 0x02, 0xC3, 0x48 },
 { 0x48, 0xD5, 0x62, 0x17, 0x06, 0x2D, 0xC4, 0xE7, 0xD5, 0xEB, 0x99, 0x78, 0x52, 0xF5, 0x16, 0x7A },
 { 0x7A, 0xE6, 0x4E, 0x1A, 0xBB, 0x2E, 0xF1, 0xBE, 0xD4, 0xAF, 0x37, 0xB1, 0xD4, 0x2A, 0x6E, 0xB8 },
 { 0xB8, 0x49, 0x87, 0x14, 0xCB, 0x8D, 0xAB, 0x49, 0x09, 0x6C, 0x2A, 0x01, 0x60, 0x8E, 0x4B, 0x5D },
 { 0x5D, 0xD4, 0xB8, 0x2F, 0x8D, 0x12, 0xEE, 0xF6, 0x08, 0x54, 0x0F, 0xF3, 0x98, 0xC8, 0x7F, 0x27 },
 { 0x27, 0x9F, 0xBE, 0x68, 0x1A, 0x7C, 0xAD, 0xC9, 0x84, 0x2F, 0xEB, 0xFE, 0xC6, 0x48, 0xA2, 0xBD },
 { 0xBD, 0x95, 0x5E, 0x30, 0xE9, 0x60, 0xBF, 0x10, 0xEF, 0x39, 0xEC, 0x91, 0x7F, 0x48, 0x89, 0x10 },
 { 0x10, 0xE9, 0xD0, 0xD9, 0xF3, 0x94, 0x3D, 0xAF, 0x7B, 0xFF, 0x64, 0x91, 0x52, 0xF8, 0x0D, 0xDD },
 { 0xDD, 0x99, 0x75, 0xCA, 0x97, 0x44, 0x5A, 0xE0, 0x30, 0xA6, 0x31, 0xD3, 0xDF, 0x48, 0x64, 0x84 },
 { 0x84, 0x2D, 0x74, 0x96, 0x5D, 0x77, 0x6F, 0xDE, 0x54, 0xB4, 0x8D, 0xD1, 0x44, 0x3C, 0xA5, 0x94 },
 { 0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01 }
};

/* ---------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_BUILTIN_XOR_SI128
 static __m128i kuz_mat_enc128[16][256];
 static __m128i kuz_mat_dec128[16][256];
#else
 static ak_uint128 kuz_mat_enc128[16][256];
 static ak_uint128 kuz_mat_dec128[16][256];
#endif

/* ---------------------------------------------------------------------------------------------- */
/*! \brief Функция умножает два элемента конечного поля \f$\mathbb F_{2^8}\f$
     согласно ГОСТ Р 34.12-2015                                                                   */
/* ---------------------------------------------------------------------------------------------- */
 static ak_uint8 ak_crypt_mul_gf256( ak_uint8 x, ak_uint8 y )
{
  ak_uint8 z = 0;
  while (y) {
    if (y & 1) z ^= x;
      x = (x << 1) ^ (x & 0x80 ? 0xC3 : 0x00);
      y >>= 1;
  }
 return z;
}

/* ---------------------------------------------------------------------------------------------- */
/*! Функция реализует линейное преобразование L согласно ГОСТ Р 34.12-2015
    (шестнадцать тактов работы линейного регистра сдвига)                                         */
/* ---------------------------------------------------------------------------------------------- */
 static void ak_crypt_kuznetchik_l1( ak_uint128 *w  )
{
  int i = 0, j = 0;
  const ak_uint8 kuz_lvec[16] = {
   0x01, 0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94
  };

  for( j = 0; j < 16; j++ ) {
     ak_uint8 z = w->b[0];
     for( i = 1; i < 16; i++ ) {
        w->b[i-1] = w->b[i];
        z ^= ak_crypt_mul_gf256( w->b[i], kuz_lvec[i] );
     }
     w->b[15] = z;
  }
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция умножает вектор w на матрицу D, результат помещается в вектор x                 */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_crypt_kuznetchik_matrix_mul_vector( const ak_uint8 D[16][16],
                                                                      ak_uint128 *w, ak_uint128* x )
{
  int i = 0, j = 0;
  for( i = 0; i < 16; i++ ) {
    ak_uint8 z = ak_crypt_mul_gf256( D[i][0], w->b[0] );
    for( j = 1; j < 16; j++ ) z ^= ak_crypt_mul_gf256( D[i][j], w->b[j] );
    x->b[i] = z;
  }
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует таблицы, необходимые для быстрой работы блочного алгоритма
    шифрования Кузнечик (ГОСТ Р 34.12-2015)                                                        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_crypt_kuznetchik_init_tables( void )
{
  int i, j, l;

#ifdef LIBAKRYPT_HAVE_BUILTIN_XOR_SI128
  ak_uint128 x, y;
  for( i = 0; i < 16; i++ ) {
     for( j = 0; j < 256; j++ ) {
        x.q[0] = 0; x.q[1] = 0;
        y.q[0] = 0; y.q[1] = 0;

        for( l = 0; l < 16; l++ ) {
           x.b[l] = ak_crypt_mul_gf256( L[l][i], pi[j] );
           y.b[l] = ak_crypt_mul_gf256( Linv[l][i], pinv[j] );
        }
      #ifdef LIBAKRYPT_HAVE_BUILTIN_SET_EPI64X
        kuz_mat_enc128[i][j] = _mm_set_epi64x(x.q[1], x.q[0]); // *((__m128i *) &x);
        kuz_mat_dec128[i][j] = _mm_set_epi64x(y.q[1], y.q[0]); // *((__m128i *) &y);
      #else
        kuz_mat_enc128[i][j].m128i_u64[0] = x.q[0]; kuz_mat_enc128[i][j].m128i_u64[1] = x.q[1];
        kuz_mat_dec128[i][j].m128i_u64[0] = y.q[0]; kuz_mat_dec128[i][j].m128i_u64[1] = y.q[1];
      #endif
     }
  }
#else
  for( i = 0; i < 16; i++ ) {
      for( j = 0; j < 256; j++ ) {
         for( l = 0; l < 16; l++ ) {
            kuz_mat_enc128[i][j].b[l] = ak_crypt_mul_gf256( L[l][i], pi[j] );
            kuz_mat_dec128[i][j].b[l] = ak_crypt_mul_gf256( Linv[l][i], pinv[j] );
         }
      }
  }
#endif
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Раундовые ключи алгоритма Кузнечик */
 typedef struct {
    ak_uint128 k[10];
 } ak_kuz_key;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура с внутренними данными секретного ключа алгоритма Кузнечик */
 struct kuznetchik_ctx {
  /*! \brief Раундовые ключи для алгоритма зашифрования */
  ak_buffer encryptkey;
  /*! \brief Раундовые ключи для алгоритма расшифрования */
  ak_buffer decryptkey;
  /*! \brief Маски, для раундовых ключей алгоритма зашифрования */
  ak_buffer encryptmask;
  /*! \brief Маски, для раундовых ключей алгоритма расшифрования */
  ak_buffer decryptmask;
 };

/* ----------------------------------------------------------------------------------------------- */
 int ak_cipher_key_kuznetchik_delete_keys( ak_skey key )
{
  struct kuznetchik_ctx *kdata = NULL;

 /* выполняем стандартные проверки */
  if( key == NULL ) {
    ak_error_message( ak_error_null_pointer, "using a null pointer to secret key", __func__ );
    return ak_error_null_pointer;
  }
  if( key->data == NULL ) {
    ak_error_message( ak_error_null_pointer, "using a null pointer to internal data", __func__ );
    return ak_error_null_pointer;
  }

  /* теперь освобождение памяти */
  kdata = ( struct kuznetchik_ctx * )key->data;

  if( kdata->encryptkey != NULL ) kdata->encryptkey = ak_buffer_delete( kdata->encryptkey );
  if( kdata->decryptkey != NULL ) kdata->decryptkey = ak_buffer_delete( kdata->decryptkey );
  if( kdata->encryptmask != NULL ) kdata->encryptmask = ak_buffer_delete( kdata->encryptmask );
  if( kdata->decryptmask != NULL ) kdata->decryptmask = ak_buffer_delete( kdata->decryptmask );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм развертки ключей для алгоритма Кузнечик (ГОСТ Р 34.12-2015)  */
 int ak_cipher_key_kuznetchik_init_keys( ak_skey key )
{
  ak_uint128 a0, a1, c, t;
  struct kuznetchik_ctx *kdata = NULL;
  ak_kuz_key *ekey = NULL, *mkey = NULL;
  ak_kuz_key *dkey = NULL, *xkey = NULL;
  int i = 0, j = 0, l = 0, idx = 0, kdx = 1;

 /* выполняем стандартные проверки */
  if( key == NULL ) {
    ak_error_message( ak_error_null_pointer, "using a null pointer to secret key", __func__ );
    return ak_error_null_pointer;
  }
  if( key->key == NULL ) {
    ak_error_message( ak_error_undefined_value, "using undefined key buffer", __func__ );
    return ak_error_undefined_value;
  }
  if( key->mask == NULL ) {
    ak_error_message( ak_error_undefined_value, "using undefined mask buffer", __func__ );
    return ak_error_undefined_value;
  }
  if( key->generator == NULL ) {
    ak_error_message( ak_error_null_pointer, "using undefined random generator", __func__ );
    return ak_error_null_pointer;
  }
  if( key->check_icode( key ) != ak_true ) {
    ak_error_message( ak_error_wrong_key_icode, "using key with wrong integrity code", __func__ );
      return ak_error_wrong_key_icode;
  }

  /* готовим память для переменных */
  if(( key->data = malloc( sizeof( struct kuznetchik_ctx ))) == NULL ) {
     ak_error_message( ak_error_out_of_memory, "wrong allocation of internal data", __func__ );
     return ak_error_out_of_memory;
  }
  kdata = ( struct kuznetchik_ctx * ) key->data;
  kdata->encryptkey = NULL;
  kdata->decryptkey = NULL;
  kdata->encryptmask = NULL;
  kdata->decryptmask = NULL;

  /* создаем необходимые массивы данных */
  if(( kdata->encryptkey = ak_buffer_new_size( sizeof( ak_kuz_key ))) == NULL ) {
    ak_error_message( ak_error_get_value(), "wrong allocation of encrypt keys memory", __func__ );
    ak_cipher_key_kuznetchik_delete_keys( key );
    return ak_error_out_of_memory;
  }
  if(( kdata->decryptkey = ak_buffer_new_size( sizeof( ak_kuz_key ))) == NULL ) {
    ak_error_message( ak_error_get_value(), "wrong allocation of decrypt keys memory", __func__ );
    ak_cipher_key_kuznetchik_delete_keys( key );
    return ak_error_out_of_memory;
  }
  if(( kdata->encryptmask = ak_buffer_new_random( key->generator, sizeof( ak_kuz_key ))) == NULL ) {
    ak_error_message( ak_error_get_value(), "wrong allocation of encrypt masks memory", __func__ );
    ak_cipher_key_kuznetchik_delete_keys( key );
    return ak_error_out_of_memory;
  }
  if(( kdata->decryptmask = ak_buffer_new_random( key->generator, sizeof( ak_kuz_key ))) == NULL ) {
    ak_error_message( ak_error_get_value(), "wrong allocation of decrypt masks memory", __func__ );
    ak_cipher_key_kuznetchik_delete_keys( key );
    return ak_error_out_of_memory;
  }

  /* только теперь выполняем алгоритм развертки ключа */
  for( i = 0; i < 16; i++ ) {
     a0.b[i] = (( ak_uint8 *) key->key->data )[i] ^ (( ak_uint8 *) key->mask->data )[i];
     a1.b[i] = (( ak_uint8 *) key->key->data )[i+16] ^ (( ak_uint8 *) key->mask->data )[i+16];
  }

  ekey = (ak_kuz_key *) ak_buffer_get_ptr( kdata->encryptkey );
  mkey = (ak_kuz_key *) ak_buffer_get_ptr( kdata->encryptmask );
  dkey = (ak_kuz_key *) ak_buffer_get_ptr( kdata->decryptkey );
  xkey = (ak_kuz_key *) ak_buffer_get_ptr( kdata->decryptmask );

  ekey->k[0].q[0] = a1.q[0]^mkey->k[0].q[0]; dkey->k[0].q[0] = a1.q[0]^xkey->k[0].q[0];
  ekey->k[0].q[1] = a1.q[1]^mkey->k[0].q[1]; dkey->k[0].q[1] = a1.q[1]^xkey->k[0].q[1];
  ekey->k[1].q[0] = a0.q[0]^mkey->k[1].q[0]; ekey->k[1].q[1] = a0.q[1]^mkey->k[1].q[1];

  ak_crypt_kuznetchik_matrix_mul_vector( Linv, &a0, &dkey->k[1] );
  dkey->k[1].q[0] ^= xkey->k[1].q[0]; dkey->k[1].q[1] ^= xkey->k[1].q[1];

  for( j = 0; j < 4; j++ ) {
     for( i = 0; i < 8; i++ ) {
        c.q[0] = ++idx; /* вычисляем константу алгоритма согласно ГОСТ Р 34.12-2015 */
        c.q[1] = 0;
        ak_crypt_kuznetchik_l1( &c );

        t.q[0] = a1.q[0] ^ c.q[0]; t.q[1] = a1.q[1] ^ c.q[1];
        for( l = 0; l < 16; l++ ) t.b[l] = pi[t.b[l]];
        ak_crypt_kuznetchik_l1( &t );

        t.q[0] ^= a0.q[0]; t.q[1] ^= a0.q[1];
        a0.q[0] = a1.q[0]; a0.q[1] = a1.q[1];
        a1.q[0] = t.q[0];  a1.q[1] = t.q[1];
     }
     kdx++;
     ekey->k[kdx].q[0] = a1.q[0]^mkey->k[kdx].q[0];
     ekey->k[kdx].q[1] = a1.q[1]^mkey->k[kdx].q[1];
     ak_crypt_kuznetchik_matrix_mul_vector( Linv, &a1, &dkey->k[kdx] );
     dkey->k[kdx].q[0] ^= xkey->k[kdx].q[0];
     dkey->k[kdx].q[1] ^= xkey->k[kdx].q[1];

     kdx++;
     ekey->k[kdx].q[0] = a0.q[0]^mkey->k[kdx].q[0];
     ekey->k[kdx].q[1] = a0.q[1]^mkey->k[kdx].q[1];
     ak_crypt_kuznetchik_matrix_mul_vector( Linv, &a0, &dkey->k[kdx] );
     dkey->k[kdx].q[0] ^= xkey->k[kdx].q[0];
     dkey->k[kdx].q[1] ^= xkey->k[kdx].q[1];
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм зашифрования одного блока информации
    шифром Кузнечик (согласно ГОСТ Р 34.12-2015)                                                   */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_crypt_kuznetchik_encrypt_with_mask( ak_skey key, ak_pointer in, ak_pointer out )
{
  int i = 0;
  ak_kuz_key *ekey = (ak_kuz_key *) (( struct kuznetchik_ctx * ) key->data)->encryptkey->data;
  ak_kuz_key *mkey = (ak_kuz_key *) (( struct kuznetchik_ctx * ) key->data)->encryptmask->data;

#ifdef LIBAKRYPT_HAVE_BUILTIN_XOR_SI128
  __m128i z, x = *((__m128i *) in);

  for( i = 0; i < 9; i++ ) {
   #ifdef LIBAKRYPT_HAVE_BUILTIN_SET_EPI64X
     x = _mm_xor_si128( x, _mm_set_epi64x( ekey->k[i].q[1], ekey->k[i].q[0] ));
     x = _mm_xor_si128( x, _mm_set_epi64x( mkey->k[i].q[1], mkey->k[i].q[0] ));
   #else
     z.m128i_u64[0] = ekey->k[i].q[0]; z.m128i_u64[1] = ekey->k[i].q[1]; x = _mm_xor_si128( x, z );
     z.m128i_u64[0] = mkey->k[i].q[0]; z.m128i_u64[1] = mkey->k[i].q[1]; x = _mm_xor_si128( x, z );
   #endif

     z = kuz_mat_enc128[ 0][((ak_uint8 *) &x)[ 0]];
     z = _mm_xor_si128( z, kuz_mat_enc128[ 1][((ak_uint8 *) &x)[ 1]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[ 2][((ak_uint8 *) &x)[ 2]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[ 3][((ak_uint8 *) &x)[ 3]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[ 4][((ak_uint8 *) &x)[ 4]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[ 5][((ak_uint8 *) &x)[ 5]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[ 6][((ak_uint8 *) &x)[ 6]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[ 7][((ak_uint8 *) &x)[ 7]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[ 8][((ak_uint8 *) &x)[ 8]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[ 9][((ak_uint8 *) &x)[ 9]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[10][((ak_uint8 *) &x)[10]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[11][((ak_uint8 *) &x)[11]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[12][((ak_uint8 *) &x)[12]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[13][((ak_uint8 *) &x)[13]]);
     z = _mm_xor_si128( z, kuz_mat_enc128[14][((ak_uint8 *) &x)[14]]);
     x = _mm_xor_si128( z, kuz_mat_enc128[15][((ak_uint8 *) &x)[15]]);
  }

 #ifdef LIBAKRYPT_HAVE_BUILTIN_SET_EPI64X
  x = _mm_xor_si128( x, _mm_set_epi64x( ekey->k[9].q[1], ekey->k[9].q[0] ));
  *((__m128i *) out) = _mm_xor_si128( x, _mm_set_epi64x( mkey->k[9].q[1], mkey->k[9].q[0] ));
 #else
  z.m128i_u64[0] = ekey->k[9].q[0]; z.m128i_u64[1] = ekey->k[9].q[1]; x = _mm_xor_si128( x, z );
  z.m128i_u64[0] = mkey->k[9].q[0]; z.m128i_u64[1] = mkey->k[9].q[1]; 
  *((__m128i *) out) = _mm_xor_si128( x, z );
 #endif

#else
  ak_uint64 t;
  ak_uint128 x;
  x.q[0] = (( ak_uint64 *) in)[0]; x.q[1] = (( ak_uint64 *) in)[1];

  for( i = 0; i < 9; i++ ) {
     x.q[0] ^= ekey->k[i].q[0]; x.q[0] ^= mkey->k[i].q[0];
     x.q[1] ^= ekey->k[i].q[1]; x.q[1] ^= mkey->k[i].q[1];

     t = kuz_mat_enc128[ 0][x.b[ 0]].q[0] ^
         kuz_mat_enc128[ 1][x.b[ 1]].q[0] ^
         kuz_mat_enc128[ 2][x.b[ 2]].q[0] ^
         kuz_mat_enc128[ 3][x.b[ 3]].q[0] ^
         kuz_mat_enc128[ 4][x.b[ 4]].q[0] ^
         kuz_mat_enc128[ 5][x.b[ 5]].q[0] ^
         kuz_mat_enc128[ 6][x.b[ 6]].q[0] ^
         kuz_mat_enc128[ 7][x.b[ 7]].q[0] ^
         kuz_mat_enc128[ 8][x.b[ 8]].q[0] ^
         kuz_mat_enc128[ 9][x.b[ 9]].q[0] ^
         kuz_mat_enc128[10][x.b[10]].q[0] ^
         kuz_mat_enc128[11][x.b[11]].q[0] ^
         kuz_mat_enc128[12][x.b[12]].q[0] ^
         kuz_mat_enc128[13][x.b[13]].q[0] ^
         kuz_mat_enc128[14][x.b[14]].q[0] ^
         kuz_mat_enc128[15][x.b[15]].q[0];

     x.q[1] = kuz_mat_enc128[ 0][x.b[ 0]].q[1] ^
         kuz_mat_enc128[ 1][x.b[ 1]].q[1] ^
         kuz_mat_enc128[ 2][x.b[ 2]].q[1] ^
         kuz_mat_enc128[ 3][x.b[ 3]].q[1] ^
         kuz_mat_enc128[ 4][x.b[ 4]].q[1] ^
         kuz_mat_enc128[ 5][x.b[ 5]].q[1] ^
         kuz_mat_enc128[ 6][x.b[ 6]].q[1] ^
         kuz_mat_enc128[ 7][x.b[ 7]].q[1] ^
         kuz_mat_enc128[ 8][x.b[ 8]].q[1] ^
         kuz_mat_enc128[ 9][x.b[ 9]].q[1] ^
         kuz_mat_enc128[10][x.b[10]].q[1] ^
         kuz_mat_enc128[11][x.b[11]].q[1] ^
         kuz_mat_enc128[12][x.b[12]].q[1] ^
         kuz_mat_enc128[13][x.b[13]].q[1] ^
         kuz_mat_enc128[14][x.b[14]].q[1] ^
         kuz_mat_enc128[15][x.b[15]].q[1];
     x.q[0] = t;
  }
  x.q[0] ^= ekey->k[9].q[0]; x.q[1] ^= ekey->k[9].q[1];
  ((ak_uint64 *)out)[0] = x.q[0] ^ mkey->k[9].q[0];
  ((ak_uint64 *)out)[1] = x.q[1] ^ mkey->k[9].q[1];
#endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм зашифрования одного блока информации
    шифром Кузнечик (согласно ГОСТ Р 34.12-2015)                                                   */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_crypt_kuznetchik_decrypt_with_mask( ak_skey key, ak_pointer in, ak_pointer out )
{
  int i = 0;
  ak_kuz_key *dkey = (ak_kuz_key *) (( struct kuznetchik_ctx * ) key->data)->decryptkey->data;
  ak_kuz_key *xkey = (ak_kuz_key *) (( struct kuznetchik_ctx * ) key->data)->decryptmask->data;

#ifdef LIBAKRYPT_HAVE_BUILTIN_XOR_SI128
  __m128i z, x = *((__m128i *) in);

  for( i = 0; i < 16; i++ ) ((ak_uint8 *) &x)[i] = pi[((ak_uint8 *) &x)[i]];
  for( i = 9; i > 0; i-- ) {
     z = kuz_mat_dec128[ 0][((ak_uint8 *) &x)[ 0]];

     z = _mm_xor_si128( z, kuz_mat_dec128[ 1][((ak_uint8 *) &x)[ 1]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[ 2][((ak_uint8 *) &x)[ 2]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[ 3][((ak_uint8 *) &x)[ 3]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[ 4][((ak_uint8 *) &x)[ 4]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[ 5][((ak_uint8 *) &x)[ 5]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[ 6][((ak_uint8 *) &x)[ 6]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[ 7][((ak_uint8 *) &x)[ 7]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[ 8][((ak_uint8 *) &x)[ 8]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[ 9][((ak_uint8 *) &x)[ 9]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[10][((ak_uint8 *) &x)[10]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[11][((ak_uint8 *) &x)[11]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[12][((ak_uint8 *) &x)[12]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[13][((ak_uint8 *) &x)[13]]);
     z = _mm_xor_si128( z, kuz_mat_dec128[14][((ak_uint8 *) &x)[14]]);
     x = _mm_xor_si128( z, kuz_mat_dec128[15][((ak_uint8 *) &x)[15]]);
   #ifdef LIBAKRYPT_HAVE_BUILTIN_SET_EPI64X
     x = _mm_xor_si128( x, _mm_set_epi64x( dkey->k[i].q[1], dkey->k[i].q[0] ));
     x = _mm_xor_si128( x, _mm_set_epi64x( xkey->k[i].q[1], xkey->k[i].q[0] ));
   #else
     z.m128i_u64[0] = dkey->k[i].q[0]; z.m128i_u64[1] = dkey->k[i].q[1]; x = _mm_xor_si128( x, z ); 
     z.m128i_u64[0] = xkey->k[i].q[0]; z.m128i_u64[1] = xkey->k[i].q[1]; x = _mm_xor_si128( x, z ); 
   #endif
  }
  for( i = 0; i < 16; i++ ) ((ak_uint8 *) &x)[i] = pinv[((ak_uint8 *) &x)[i]];

 #ifdef LIBAKRYPT_HAVE_BUILTIN_SET_EPI64X
  x = _mm_xor_si128( x, _mm_set_epi64x( dkey->k[0].q[1], dkey->k[0].q[0] ));
  *((__m128i *) out) = _mm_xor_si128( x, _mm_set_epi64x( xkey->k[0].q[1], xkey->k[0].q[0] ));
 #else
  z.m128i_u64[0] = dkey->k[0].q[0]; z.m128i_u64[1] = dkey->k[0].q[1]; x = _mm_xor_si128( x, z );
  z.m128i_u64[0] = xkey->k[0].q[0]; z.m128i_u64[1] = xkey->k[0].q[1]; 
  *((__m128i *) out) = _mm_xor_si128( x, z );
 #endif

#else
  ak_uint64 t;
  ak_uint128 x;

  x.q[0] = (( ak_uint64 *) in)[0]; x.q[1] = (( ak_uint64 *) in)[1];
  for( i = 0; i < 16; i++ ) x.b[i] = pi[x.b[i]];
  for( i = 9; i > 0; i-- ) {
     t = kuz_mat_dec128[ 0][x.b[ 0]].q[0] ^
         kuz_mat_dec128[ 1][x.b[ 1]].q[0] ^
         kuz_mat_dec128[ 2][x.b[ 2]].q[0] ^
         kuz_mat_dec128[ 3][x.b[ 3]].q[0] ^
         kuz_mat_dec128[ 4][x.b[ 4]].q[0] ^
         kuz_mat_dec128[ 5][x.b[ 5]].q[0] ^
         kuz_mat_dec128[ 6][x.b[ 6]].q[0] ^
         kuz_mat_dec128[ 7][x.b[ 7]].q[0] ^
         kuz_mat_dec128[ 8][x.b[ 8]].q[0] ^
         kuz_mat_dec128[ 9][x.b[ 9]].q[0] ^
         kuz_mat_dec128[10][x.b[10]].q[0] ^
         kuz_mat_dec128[11][x.b[11]].q[0] ^
         kuz_mat_dec128[12][x.b[12]].q[0] ^
         kuz_mat_dec128[13][x.b[13]].q[0] ^
         kuz_mat_dec128[14][x.b[14]].q[0] ^
         kuz_mat_dec128[15][x.b[15]].q[0];

     x.q[1] = kuz_mat_dec128[ 0][x.b[ 0]].q[1] ^
         kuz_mat_dec128[ 1][x.b[ 1]].q[1] ^
         kuz_mat_dec128[ 2][x.b[ 2]].q[1] ^
         kuz_mat_dec128[ 3][x.b[ 3]].q[1] ^
         kuz_mat_dec128[ 4][x.b[ 4]].q[1] ^
         kuz_mat_dec128[ 5][x.b[ 5]].q[1] ^
         kuz_mat_dec128[ 6][x.b[ 6]].q[1] ^
         kuz_mat_dec128[ 7][x.b[ 7]].q[1] ^
         kuz_mat_dec128[ 8][x.b[ 8]].q[1] ^
         kuz_mat_dec128[ 9][x.b[ 9]].q[1] ^
         kuz_mat_dec128[10][x.b[10]].q[1] ^
         kuz_mat_dec128[11][x.b[11]].q[1] ^
         kuz_mat_dec128[12][x.b[12]].q[1] ^
         kuz_mat_dec128[13][x.b[13]].q[1] ^
         kuz_mat_dec128[14][x.b[14]].q[1] ^
         kuz_mat_dec128[15][x.b[15]].q[1];

      x.q[0] = t;
      x.q[0] ^= dkey->k[i].q[0]; x.q[1] ^= dkey->k[i].q[1];
      x.q[0] ^= xkey->k[i].q[0]; x.q[1] ^= xkey->k[i].q[1];
  }
  for( i = 0; i < 16; i++ ) x.b[i] = pinv[x.b[i]];

  x.q[0] ^= dkey->k[0].q[0]; x.q[1] ^= dkey->k[0].q[1];
  (( ak_uint64 *) out)[0] = x.q[0] ^ xkey->k[0].q[0];
  (( ak_uint64 *) out)[1] = x.q[1] ^ xkey->k[0].q[1];
#endif
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_cipher_key_kuznetchik_remask_xor( ak_skey key )
{
  size_t idx, keylen = 0;
  struct kuznetchik_ctx *kdata = NULL;
  ak_buffer newmask = NULL;
  ak_kuz_key *ekey = NULL, *mkey = NULL, *newkey = NULL;
  int error = ak_skey_remask_xor(key);

 /* вначале маскируем ключ */
  if( error != ak_error_ok ) {
   ak_error_message( error, "wrong key remasking", __func__ );
   return error;
  };
 /* проверяем наличие развертки ключа */
  if( key->data == NULL ) {
    ak_error_message( ak_error_undefined_value, "using context with non initialized data", __func__ );
    return ak_error_undefined_value;
  }

 /* создаем новый буффер */
  kdata = ( struct kuznetchik_ctx * ) key->data;
  keylen = ak_buffer_get_size( kdata->encryptkey );
  if(( newmask = ak_buffer_new_random( key->generator, keylen )) == NULL ) {
     ak_error_message( ak_error_out_of_memory, "wrong mask buffer generation", __func__ );
     return ak_error_out_of_memory;
   }
 /* накладываем маску */
  ekey = (ak_kuz_key *) ak_buffer_get_ptr( kdata->encryptkey );
  mkey = (ak_kuz_key *) ak_buffer_get_ptr( kdata->encryptmask );
  newkey = (ak_kuz_key *) ak_buffer_get_ptr( newmask );
  for( idx = 0; idx < 10; idx++ ) {
     ekey->k[idx].q[0] ^= newkey->k[idx].q[0]; ekey->k[idx].q[0] ^= mkey->k[idx].q[0];
     ekey->k[idx].q[1] ^= newkey->k[idx].q[1]; ekey->k[idx].q[1] ^= mkey->k[idx].q[1];
  }
  ak_buffer_delete( kdata->encryptmask );
  kdata->encryptmask = newmask;

 /* создаем новый буффер */
  if(( newmask = ak_buffer_new_random( key->generator, keylen )) == NULL ) {
     ak_error_message( ak_error_out_of_memory, "wrong mask buffer generation", __func__ );
     return ak_error_out_of_memory;
  }
 /* накладываем маску */
  ekey = (ak_kuz_key *) ak_buffer_get_ptr( kdata->decryptkey );
  mkey = (ak_kuz_key *) ak_buffer_get_ptr( kdata->decryptmask );
  newkey = (ak_kuz_key *) ak_buffer_get_ptr( newmask );
  for( idx = 0; idx < 10; idx++ ) {
     ekey->k[idx].q[0] ^= newkey->k[idx].q[0]; ekey->k[idx].q[0] ^= mkey->k[idx].q[0];
     ekey->k[idx].q[1] ^= newkey->k[idx].q[1]; ekey->k[idx].q[1] ^= mkey->k[idx].q[1];
  }
  ak_buffer_delete( kdata->decryptmask );
  kdata->decryptmask = newmask;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция создает контекст ключа блочного алгоритма шифрования Кузнечик (ГОСТ Р 34.12-2015).

    После выполнения данной функции создается указатель на контекст ключа и устанавливаются
    обработчики (функции класса). Однако само значение ключу не присваивается -
    поле key->key остается равным NULL.

    \b Внимание. Данная функция предназначена для использования другими функциями и не должна
    вызываться напрямую.

    @return Функция возвращает указатель на созданный контекст. В случае возникновения ошибки,
    возвращается NULL, код ошибки может быть получен с помощью вызова функции ak_error_get_value() */
/* ----------------------------------------------------------------------------------------------- */
 ak_cipher_key ak_cipher_key_new_kuznetchik( void )
{
  ak_cipher_key ckey = NULL;

 /* создаем ключ алгоритма шифрования и определяем его методы */
  if(( ckey = ak_cipher_key_new()) == NULL ) {
     ak_error_message( ak_error_null_pointer, "incorrect memory allocation", __func__ );
     return NULL;
  }
 /* создаем область для хранения ключевых данных */
  if(( ckey->key->key = ak_buffer_new_function_size( malloc, free, 32 )) == NULL ) {
    ak_error_message( ak_error_get_value(), "incorrect memory allocation for key buffer", __func__ );
    return ( ckey = ak_cipher_key_delete( ckey ));
  }
 /* устанавливаем OID алгоритма шифрования */
  ckey->oid = ak_oids_find_by_name( "kuznetchik" );
 /* устанавливаем ресурс использования серетного ключа */
  ckey->resource = ak_libakrypt_get_kuznetchik_resource();
 /* устанавливаем размер блока обрабатываемых данных (в байтах) */
  ckey->block_size = 16;  /* длина блока для алгоритма Кузнечик равна 128 бит */
 /* присваиваем ключу уникальный номер */
  if( ak_skey_assign_unique_number( ckey->key ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), "incorrect calculation of unique key number", __func__ );
    return ( ckey = ak_cipher_key_delete( ckey ));
  }

 /* устанавливаем методы */
  ckey->key->set_mask = ak_skey_set_mask_xor;
  ckey->key->remask = ak_cipher_key_kuznetchik_remask_xor;
  ckey->key->set_icode = ak_skey_set_icode_xor;
  ckey->key->check_icode = ak_skey_check_icode_xor;

  ckey->init_keys = ak_cipher_key_kuznetchik_init_keys;
  ckey->delete_keys = ak_cipher_key_kuznetchik_delete_keys;
  ckey->encrypt = ak_crypt_kuznetchik_encrypt_with_mask;
  ckey->decrypt = ak_crypt_kuznetchik_decrypt_with_mask;

 return ckey;
}

/* ----------------------------------------------------------------------------------------------- */
/*! После выполнения данной функции создается указатель на контекст ключа,
    значение которого содержится в заданном буффере.
    После создания ключа производится его маскирование, выработка контрольной суммы,
    после чего доступ к ключу закрывается с помощью вызова функции ak_skey_lock().

    Предпалагается, что основное использование функции ak_cipher_key_new_kuxnetchik_buffer()
    заключается в тестировании алгоритма шифрования Кузнечик (ГОСТ Р 34.12-2015)
    на заданных (тестовых) значениях ключей.

    @param buff Буффер, содержащий ключевое значение.
    \b Важно: после выполнения функции владение буффером переходит к контексту алгоритма шифрования,
    создаваемому функцией.

    @return Функция возвращает указатель на созданный контекст. В случае возникновения ошибки,
    возвращается NULL, код ошибки может быть получен с помощью вызова функции ak_error_get_value() */
/* ----------------------------------------------------------------------------------------------- */
 ak_cipher_key ak_cipher_key_new_kuznetchik_buffer( ak_buffer buff )
{
  ak_cipher_key ckey = NULL;

 /* проверяем входной буффер */
  if( buff == NULL ) {
    ak_error_message( ak_error_null_pointer, "using a null pointer to buffer", __func__ );
    return NULL;
  }
 /* создаем контекст ключа */
  if(( ckey = ak_cipher_key_new_kuznetchik()) == NULL ) {
     ak_error_message( ak_error_get_value(), "incorrect creation of magma secret key", __func__ );
     return NULL;
  }
 /* присваиваем ключевой буффер */
  if( ak_skey_assign_buffer( ckey->key, buff ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), "incorrect assigning of key buffer", __func__ );
    return ( ckey = ak_cipher_key_delete( ckey ));
  }
 /* инициализируем раундовые ключи */
  if( ckey->init_keys( ckey->key ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), "incorrect initialization of round keys", __func__ );
    return ( ckey = ak_cipher_key_delete( ckey ));
  }
 /* выводим сообщение о факте создания ключа */
  if( ak_log_get_level() >= ak_log_standard ) ak_error_message_fmt( ak_error_ok, __func__ ,
                               "created a secret key %s", ak_buffer_get_str(ckey->key->number ));
 /* закрываем доступ к секретному ключу */
  if( ak_skey_lock( ckey->key ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), "incorrect locking of secret key", __func__ );
    return ( ckey = ak_cipher_key_delete( ckey ));
  }
 return ckey;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_cipher_key ak_cipher_key_new_kuznetchik_random( ak_random generator )
{
  ak_cipher_key ckey = NULL;

 /* проверяем входной буффер */
  if( generator == NULL ) {
    ak_error_message( ak_error_null_pointer, "using a null pointer to random generator", __func__ );
    return NULL;
  }
 /* создаем контекст ключа */
  if(( ckey = ak_cipher_key_new_kuznetchik()) == NULL ) {
    ak_error_message( ak_error_get_value(), "incorrect creation of magma secret key", __func__ );
    return NULL;
  }
 /* присваиваем случайные данные, выработанные генератором */
  if(( ak_random_ptr( generator,
    ak_buffer_get_ptr( ckey->key->key ), ak_buffer_get_size( ckey->key->key ))) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), "incorrect generation a random key data", __func__ );
    return ( ckey = ak_cipher_key_delete( ckey ));
  }
 /* накладываем маску */
  if( ckey->key->set_mask( ckey->key ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), "wrong secret key masking", __func__ );
    return ( ckey = ak_cipher_key_delete( ckey ));
  }
 /* вычисляем контрольную сумму */
  if( ckey->key->set_icode( ckey->key ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), "wrong calculation of integrity code", __func__ );
    return ( ckey = ak_cipher_key_delete( ckey ));
  }
 /* инициализируем раундовые ключи */
  if( ckey->init_keys( ckey->key ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), "incorrect initialization of round keys", __func__ );
    return ( ckey = ak_cipher_key_delete( ckey ));
  }
 /* выводим сообщение о факте создания ключа */
  if( ak_log_get_level() >= ak_log_standard ) ak_error_message_fmt( ak_error_ok, __func__ ,
                              "created a secret key %s", ak_buffer_get_str(ckey->key->number ));
 /* закрываем доступ к секретному ключу */
  if( ak_skey_lock( ckey->key ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), "incorrect locking of secret key", __func__ );
    return ( ckey = ak_cipher_key_delete( ckey ));
  }
 return ckey;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция выполняет тестирование блочного алгоритма Кузнечик в соответствии
    с ГОСТ Р 34.12-2015 и ГОСТ Р 34.13-2015.                                                       */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_cipher_key_test_kuznetchik( void )
{
  char *str = NULL;
  ak_cipher_key ckey = NULL;
  int audit = ak_log_get_level();

  ak_uint8 test3412_key[32] = {
    0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88
  };
  ak_uint8 in[16] = {
   0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
  };
  ak_uint8 out[16] = {
   0xcd, 0xed, 0xd4, 0xb9, 0x42, 0x8d, 0x46, 0x5a, 0x30, 0x24, 0xbc, 0xbe, 0x90, 0x9d, 0x67, 0x7f
  };
  ak_uint32 inlong[16] = {
    0xbbaa9988, 0xffeeddcc, 0x55667700, 0x11223344, 0xcceeff0a, 0x8899aabb, 0x44556677, 0x00112233,
    0xeeff0a00, 0x99aabbcc, 0x55667788, 0x11223344, 0xff0a0011, 0xaabbccee, 0x66778899, 0x22334455
  };
  ak_uint32 outecb[16] = {
    0xb9d4edcd, 0x5a468d42, 0xbebc2430, 0x7f679d90, 0x6718d08b, 0x285452d7, 0x6e0032f9, 0xb429912c,
    0x3bd4b157, 0xf3f5a531, 0x9d247cee, 0xf0ca3354, 0xaa8ada98, 0x3a02c4c5, 0xe830b9eb, 0xd0b09ccd
  };
  ak_uint8 result[64];

 /* 1. Выполняем тестовый пример из ГОСТ 34.12-2015 */
  if(( ckey = ak_cipher_key_new_kuznetchik_buffer(
                                  ak_buffer_new_ptr( test3412_key, 32, ak_false ))) == NULL ) {
    ak_error_message( ak_error_get_value(), "wrong creation of secret key", __func__ );
    return ak_false;
   }
   memset( result, 0, 16 );
   ckey->encrypt( ckey->key, in, result );
   if( memcmp( result, out, 16 ) != 0  ) {
     ak_error_message( ak_error_not_equal_data,
                     "the one block encryption test from GOST R 34.12-2015 is wrong", __func__ );
     ak_log_set_message(( str = ak_ptr_to_hexstr( result, 16, ak_false ))); free( str );
     ak_log_set_message(( str = ak_ptr_to_hexstr( out, 16, ak_false ))); free( str );
     ckey = ak_cipher_key_delete( ckey );
     return ak_false;
   }
   if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok,
                        "the one block encryption test from GOST R 34.12-2015 is Ok", __func__ );
   memset( result, 0, 16 );
   ckey->decrypt( ckey->key, out, result );
   if( memcmp( result, in, 16 ) != 0 ) {
     ak_error_message( ak_error_not_equal_data,
                     "the one block decryption test from GOST R 34.12-2015 is wrong", __func__ );
     ak_log_set_message(( str = ak_ptr_to_hexstr( result, 16, ak_false ))); free( str );
     ak_log_set_message(( str = ak_ptr_to_hexstr( in, 16, ak_false ))); free( str );
     ckey = ak_cipher_key_delete( ckey );
     return ak_false;
   }
   if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok,
                        "the one block decryption test from GOST R 34.12-2015 is Ok", __func__ );

  /* 2. Выполняем пример из ГОСТ 34.13-2015 для режима простой замены (ECB) */
   memset( result, 0, 64 );
   ak_cipher_key_encrypt_ecb( ckey, inlong, result, 64 );
   if( memcmp( outecb, result, 64 ) != 0 ) {
     ak_error_message( ak_error_not_equal_data,
                        "the ecb mode encryption test from GOST 34.13-2015 is wrong", __func__ );
     ak_log_set_message(( str = ak_ptr_to_hexstr( result, 64, ak_false ))); free( str );
     ak_log_set_message(( str = ak_ptr_to_hexstr( outecb, 64, ak_false ))); free( str );
     ckey = ak_cipher_key_delete( ckey );
     return ak_false;
   }
   if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok,
                           "the ecb mode encryption test from GOST 34.13-2015 is Ok", __func__ );
   memset( result, 0, 64 );
   ak_cipher_key_decrypt_ecb( ckey, outecb, result, 64 );
   if( memcmp( inlong, result, 64 ) != 0 ) {
     ak_error_message( ak_error_not_equal_data,
                        "the ecb mode decryption test from GOST 34.13-2015 is wrong", __func__ );
     ak_log_set_message(( str = ak_ptr_to_hexstr( result, 64, ak_false ))); free( str );
     ak_log_set_message(( str = ak_ptr_to_hexstr( inlong, 64, ak_false ))); free( str );
     ckey = ak_cipher_key_delete( ckey );
     return ak_false;
   }
   if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok,
                           "the ecb mode decryption test from GOST 34.13-2015 is Ok", __func__ );

   ckey = ak_cipher_key_delete( ckey );
 return ak_true;
}
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                ak_kuznetchik.c  */
/* ----------------------------------------------------------------------------------------------- */
