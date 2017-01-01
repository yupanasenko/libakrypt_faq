/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2008 - 2010, 2016 by Axel Kenzo, axelkenzo@mail.ru                              */
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
/*   ak_gosthash.c                                                                                 */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_oid.h>
 #include <ak_parameters.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция преобразует перестановки, заданные двумерным массивом k размера 8x16,
    в четыре одномерных массива.
    @param k   указатель на двумерный массив, состоящий из 8ми массивов четырех битных перестановок
    @param k21 указатель на одномерный массив
    @param k43 указатель на одномерный массив
    @param k65 указатель на одномерный массив
    @param k87 указатель на одномерный массив
    @return Функция возвращает либо ak_error_null_pointer, если хотя бы один из
    указателей не определен. В случае успешного преобразования возвращается ak_error_ok.           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_kbox_to_sbox( const ak_kbox k, sbox k21, sbox k43, sbox k65, sbox k87 )
{
 int i = 0;
 if( k == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to kbox set" );
   return ak_error_null_pointer;
 }
 if( k21 == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to k21 sbox" );
   return ak_error_null_pointer;
 }
 if( k43 == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to k43 sbox" );
   return ak_error_null_pointer;
   }
 if( k65 == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to k65 sbox" );
   return ak_error_null_pointer;
 }
 if( k87 == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to k87 sbox" );
   return ak_error_null_pointer;
 }
 /* мы выполняем преобразование в предположении, что под указатели корректно распределена память */
 /* в противном случае, функция может привести к выходу за пределы массива */
 for ( i = 0; i < 256; i++ ) {
        k87[i] = (*k)[7][i >> 4] << 4 | (*k)[6][i & 15];
        k65[i] = (*k)[5][i >> 4] << 4 | (*k)[4][i & 15];
        k43[i] = (*k)[3][i >> 4] << 4 | (*k)[2][i & 15];
        k21[i] = (*k)[1][i >> 4] << 4 | (*k)[0][i & 15];
 }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует один такт шифрующего преобразования ГОСТ 28147-89                            */
 static ak_uint32 ak_crypt_magma_gostf( ak_uint32 x, const ak_uint8* k21,
                                     const ak_uint8 *k43, const ak_uint8* k65, const ak_uint8 *k87 )
{
  x = k87[x>>24 & 255] << 24 | k65[x>>16 & 255] << 16 | k43[x>> 8 & 255] <<  8 | k21[x & 255];
  return x<<11 | x>>(32-11);
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция зашифрования ГОСТ 28147-89 в режиме простой замены                                     */
 static void ak_crypt_magma_encrypt( const ak_uint32 in[2], ak_uint32 out[2],
                            const ak_uint32 key[8], const ak_uint8* k21,
                                     const ak_uint8 *k43, const ak_uint8* k65, const ak_uint8 *k87 )
{
  register ak_uint32 n1 = in[0], n2 = in[1];

         n2 ^= ak_crypt_magma_gostf( n1+key[0], k21, k43, k65, k87 );
         n1 ^= ak_crypt_magma_gostf( n2+key[1], k21, k43, k65, k87 );
         n2 ^= ak_crypt_magma_gostf( n1+key[2], k21, k43, k65, k87 );
         n1 ^= ak_crypt_magma_gostf( n2+key[3], k21, k43, k65, k87 );
         n2 ^= ak_crypt_magma_gostf( n1+key[4], k21, k43, k65, k87 );
         n1 ^= ak_crypt_magma_gostf( n2+key[5], k21, k43, k65, k87 );
         n2 ^= ak_crypt_magma_gostf( n1+key[6], k21, k43, k65, k87 );
         n1 ^= ak_crypt_magma_gostf( n2+key[7], k21, k43, k65, k87 );

         n2 ^= ak_crypt_magma_gostf( n1+key[0], k21, k43, k65, k87 );
         n1 ^= ak_crypt_magma_gostf( n2+key[1], k21, k43, k65, k87 );
         n2 ^= ak_crypt_magma_gostf( n1+key[2], k21, k43, k65, k87 );
         n1 ^= ak_crypt_magma_gostf( n2+key[3], k21, k43, k65, k87 );
         n2 ^= ak_crypt_magma_gostf( n1+key[4], k21, k43, k65, k87 );
         n1 ^= ak_crypt_magma_gostf( n2+key[5], k21, k43, k65, k87 );
         n2 ^= ak_crypt_magma_gostf( n1+key[6], k21, k43, k65, k87 );
         n1 ^= ak_crypt_magma_gostf( n2+key[7], k21, k43, k65, k87 );

         n2 ^= ak_crypt_magma_gostf( n1+key[0], k21, k43, k65, k87 );
         n1 ^= ak_crypt_magma_gostf( n2+key[1], k21, k43, k65, k87 );
         n2 ^= ak_crypt_magma_gostf( n1+key[2], k21, k43, k65, k87 );
         n1 ^= ak_crypt_magma_gostf( n2+key[3], k21, k43, k65, k87 );
         n2 ^= ak_crypt_magma_gostf( n1+key[4], k21, k43, k65, k87 );
         n1 ^= ak_crypt_magma_gostf( n2+key[5], k21, k43, k65, k87 );
         n2 ^= ak_crypt_magma_gostf( n1+key[6], k21, k43, k65, k87 );
         n1 ^= ak_crypt_magma_gostf( n2+key[7], k21, k43, k65, k87 );

         n2 ^= ak_crypt_magma_gostf( n1+key[7], k21, k43, k65, k87 );
         n1 ^= ak_crypt_magma_gostf( n2+key[6], k21, k43, k65, k87 );
         n2 ^= ak_crypt_magma_gostf( n1+key[5], k21, k43, k65, k87 );
         n1 ^= ak_crypt_magma_gostf( n2+key[4], k21, k43, k65, k87 );
         n2 ^= ak_crypt_magma_gostf( n1+key[3], k21, k43, k65, k87 );
         n1 ^= ak_crypt_magma_gostf( n2+key[2], k21, k43, k65, k87 );
         n2 ^= ak_crypt_magma_gostf( n1+key[1], k21, k43, k65, k87 );
         n1 ^= ak_crypt_magma_gostf( n2+key[0], k21, k43, k65, k87 );

         out[0] = n2; out[1] = n1;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура для хранения внутренних данных контекста функции хеширования ГОСТ Р 34.11-94  */
 struct gosthash94_ctx {
   /*! \brief k-боксы   */
    sbox k21, k43, k65, k87;
   /*! \brief Частичная сумма */
    ak_uint32 sum[8];
   /*! \brief Длина сообщения (в битах) */
    ak_uint32 len[8];
   /*! \brief Текущее значение хеш-функции */
    ak_uint32 hvec[8];
};

/* ----------------------------------------------------------------------------------------------- */
/*! Функция очистки контекста                                                                      */
 static void ak_hash_gosthash94_clean( ak_hash ctx )
{
  struct gosthash94_ctx *sx = NULL;
  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to a context" );
    return;
  }
  sx = ( struct gosthash94_ctx * ) ctx->data;
  /* мы очищаем данные, не трогая таблицы замен */
  memset( sx->sum, 0, 32 );
  memset( sx->len, 0, 32 );
  memset( sx->hvec, 0, 32 );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция возвращает результат вычислений                                                        */
 static void ak_hash_gosthash94_get_code( ak_hash ctx, ak_pointer out )
{
  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to a context" );
    return;
  }
  memcpy( out, (( struct gosthash94_ctx * ) ctx->data )->hvec, ctx->hsize );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция выполняет сложение двух двоичных векторов как целых чисел,
    по модулю целого числа \f$ 2^{256} \f$. Данная фунция регламентирована ГОСТ Р 34.11-94
    как функция сложения блоков хешируемого текста.

    @param left Массив даннх, к которому происходит прибавление
    @param right Массив данных, который прибавляется
    @param n Параметр n задает число байт в массиве right.  Значение данной величины должно
    находиться в пределах \f$ 0 \leq n \leq 32 \f$.

    \b Внимание. Функция потенциально опасна - она не проверяет передаваемые указатели и
    длины обрабатываемых массивов.                                                                 */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_hash_gosthash94_addition( ak_uint8 *left, const ak_uint8 *right, const ak_uint32 n )
{
   ak_uint32 i, sum, carry = 0;

    for( i = 0; i < n; i++ )
   {
     sum = (ak_uint32) left[i] + (ak_uint32) right[i] + carry;
     left[i] = sum & 0xff;
     carry = sum>>8;
   }
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует сжимающее преобразование, которое добавляет вектор in к текущему значению
    функции хеширования. Вектотр in должен иметь длину 256 бит (32 байта).

     Реализация заключительного преобразования функции взята из библиотеки
     gosthash, автор Markku-Juhani Saarinen <mjos@ssh.fi>

     @param ctx контекст алгоритма ГОСТ Р 34.11-94, обрабатывающий информацию
     @param in Блок обрабатываемых данных длины 256 бит (32 байта)                                 */
/* ----------------------------------------------------------------------------------------------- */
 static void ak_hash_gosthash94_compress( struct gosthash94_ctx *sx, const ak_uint32 *in )
{
   ak_uint32 idx = 0, *u = NULL, *v = NULL, key[8], s[8];
   ak_uint64 U[4], V[4], W[4];
   ak_uint8 *kptr = (ak_uint8 *) key, *wptr = (ak_uint8 *) W;

    memcpy( U, sx->hvec, 32 ); // U = H
    memcpy( V, in, 32 );   // V = M
    W[0] = U[0]^V[0];  W[1] = U[1]^V[1]; // W = U xor V
    W[2] = U[2]^V[2];  W[3] = U[3]^V[3];

    lb:
       // перестановка Р
        kptr[0]  = wptr[0];  kptr[4]  = wptr[1];  kptr[8]  = wptr[2];
        kptr[12] = wptr[3];  kptr[16] = wptr[4];  kptr[20] = wptr[5];
        kptr[24] = wptr[6];  kptr[28] = wptr[7];  kptr[1]  = wptr[8];
        kptr[5]  = wptr[9];  kptr[9]  = wptr[10]; kptr[13] = wptr[11];
        kptr[17] = wptr[12]; kptr[21] = wptr[13]; kptr[25] = wptr[14];
        kptr[29] = wptr[15]; kptr[2]  = wptr[16]; kptr[6]  = wptr[17];
        kptr[10] = wptr[18]; kptr[14] = wptr[19]; kptr[18] = wptr[20];
        kptr[22] = wptr[21]; kptr[26] = wptr[22]; kptr[30] = wptr[23];
        kptr[3]  = wptr[24]; kptr[7]  = wptr[25]; kptr[11] = wptr[26];
        kptr[15] = wptr[27]; kptr[19] = wptr[28]; kptr[23] = wptr[29];
        kptr[27] = wptr[30]; kptr[31] = wptr[31];
       // выше мы развернули следующий простой код
       //  for( ak_uint32 i = 0; i < 4; i++ )
       //   for( ak_uint32 j = 0; j < 8; j++ ) kptr[i + 4*j] = wptr[8*i + j];

       // шифруем
       ak_crypt_magma_encrypt( sx->hvec+idx, s+idx, key, sx->k21, sx->k43, sx->k65, sx->k87 );

       // линейное преобразование ключей
       if( idx != 6 )
      {
        // alinear64( U, U );
        ak_uint64 dp = U[0]^U[1], dps = 0;
        U[0] = U[1]; U[1] = U[2]; U[2] = U[3]; U[3] = dp;

        if( idx == 2 ) {
          U[0] ^= 0xff00ff00ff00ff00LL; U[1] ^= 0x00ff00ff00ff00ffLL;
          U[2] ^= 0xff0000ff00ffff00LL; U[3] ^= 0xff00ffff000000ffLL;
        }

        // упрощаем вызов alinear64( V, V ); alinear64( V, V );
        dp = V[0]^V[1];
        dps = V[1]^V[2];
        V[0] = V[2]; V[1] = V[3]; V[2] = dp; V[3] = dps;

        // W = U xor V
        W[0] = U[0]^V[0];  W[1] = U[1]^V[1];
        W[2] = U[2]^V[2];  W[3] = U[3]^V[3];

        idx += 2; goto lb;
      }

      //  заключительное перемешивание:
      //  идейно можно было бы реализовать так, но медленно ... ;(
      //   for( int i = 0; i < 12; i++ ) alinear16(s);
      //   for( int i = 0; i < 8; i++ ) s[i] ^= in[i];
      //   alinear16(s);
      //   for( int i = 0; i < 8; i++ ) hvec[i] ^= s[i];
      //   for( int i = 0; i < 61; i++ ) alinear16( hvec );


      // поэтому приходится действовать так ...
         u = (ak_uint32 *) U;
         v = (ak_uint32 *) V;
         u[0] = in[0] ^ s[6];
         u[1] = in[1] ^ s[7];
         u[2] = in[2] ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[0] & 0xffff) ^ (s[1] & 0xffff) ^ (s[1] >> 16) ^ (s[2] << 16) ^ s[6] ^ (s[6] << 16) ^ (s[7] & 0xffff0000) ^ (s[7] >> 16);
         u[3] = in[3] ^ (s[0] & 0xffff) ^ (s[0] << 16) ^ (s[1] & 0xffff) ^ (s[1]                                                                           << 16)
             ^ (s[1] >> 16) ^ (s[2] << 16) ^ (s[2] >> 16) ^ (s[3] << 16) ^ s[6] ^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] & 0xffff) ^ (s[7] << 16) ^ (s[7] >> 16);
         u[4] = in[4] ^ (s[0] & 0xffff0000) ^ (s[0] << 16) ^ (s[0] >> 16) ^
             (s[1] & 0xffff0000) ^ (s[1] >> 16) ^ (s[2] << 16) ^ (s[2] >> 16) ^ (s[3] << 16) ^ (s[3] >> 16) ^ (s[4] << 16) ^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] & 0xffff) ^ (s[7] << 16) ^ (s[7] >> 16);
         u[5] = in[5] ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[0] & 0xffff0000) ^
             (s[1] & 0xffff) ^ s[2] ^ (s[2] >> 16) ^ (s[3] << 16) ^ (s[3] >>
                                                                     16) ^ (s[4] << 16) ^ (s[4] >> 16) ^ (s[5] << 16) ^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] & 0xffff0000) ^ (s[7] << 16) ^ (s[7] >> 16);
         u[6] = in[6] ^ s[0] ^ (s[1] >> 16) ^ (s[2] << 16) ^ s[3] ^ (s[3] >> 16)
             ^ (s[4] << 16) ^ (s[4] >> 16) ^ (s[5] << 16) ^ (s[5] >> 16) ^ s[6] ^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] << 16);
         u[7] = in[7] ^ (s[0] & 0xffff0000) ^ (s[0] << 16) ^ (s[1] & 0xffff) ^
             (s[1] << 16) ^ (s[2] >> 16) ^ (s[3] << 16) ^ s[4] ^ (s[4] >> 16) ^ (s[5] << 16) ^ (s[5] >> 16) ^ (s[6] >> 16) ^ (s[7] & 0xffff) ^ (s[7] << 16) ^ (s[7] >> 16);

         v[0] = sx->hvec[0] ^ (u[1] << 16) ^ (u[0] >> 16);
         v[1] = sx->hvec[1] ^ (u[2] << 16) ^ (u[1] >> 16);
         v[2] = sx->hvec[2] ^ (u[3] << 16) ^ (u[2] >> 16);
         v[3] = sx->hvec[3] ^ (u[4] << 16) ^ (u[3] >> 16);
         v[4] = sx->hvec[4] ^ (u[5] << 16) ^ (u[4] >> 16);
         v[5] = sx->hvec[5] ^ (u[6] << 16) ^ (u[5] >> 16);
         v[6] = sx->hvec[6] ^ (u[7] << 16) ^ (u[6] >> 16);
         v[7] = sx->hvec[7] ^ (u[0] & 0xffff0000) ^ (u[0] << 16) ^ (u[7] >> 16) ^ (u[1] & 0xffff0000) ^ (u[1] << 16) ^ (u[6] << 16) ^ (u[7] & 0xffff0000);

         sx->hvec[0] =
             (v[0] & 0xffff0000) ^ (v[0] << 16) ^ (v[0] >> 16) ^ (v[1] >> 16) ^
             (v[1] & 0xffff0000) ^ (v[2] << 16) ^ (v[3] >> 16) ^ (v[4] << 16) ^ (v[5] >> 16) ^ v[5] ^ (v[6] >> 16) ^ (v[7] << 16) ^ (v[7] >> 16) ^ (v[7] & 0xffff);
         sx->hvec[1] =
             (v[0] << 16) ^ (v[0] >> 16) ^ (v[0] & 0xffff0000) ^ (v[1] &
                                                                  0xffff) ^ v[2] ^ (v[2] >> 16) ^ (v[3] << 16) ^ (v[4] >> 16) ^ (v[5] << 16) ^ (v[6] << 16) ^ v[6] ^ (v[7] & 0xffff0000) ^ (v[7] >> 16);
         sx->hvec[2] =
             (v[0] & 0xffff) ^ (v[0] << 16) ^ (v[1] << 16) ^ (v[1] >> 16) ^
             (v[1] & 0xffff0000) ^ (v[2] << 16) ^ (v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^ (v[5] >> 16) ^ v[6] ^ (v[6] >> 16) ^ (v[7] & 0xffff) ^ (v[7] << 16) ^ (v[7] >> 16);
         sx->hvec[3] = (v[0] << 16) ^ (v[0] >> 16) ^ (v[0] & 0xffff0000) ^ (v[1] & 0xffff0000)
             ^ (v[1] >> 16) ^ (v[2] << 16) ^ (v[2] >> 16) ^ v[2] ^ (v[3] << 16) ^ (v[4] >> 16) ^ v[4] ^ (v[5] << 16) ^ (v[6] << 16) ^ (v[7] & 0xffff) ^ (v[7] >> 16);
         sx->hvec[4] = (v[0] >> 16) ^ (v[1] << 16) ^ v[1] ^ (v[2] >> 16) ^ v[2] ^ (v[3] << 16) ^ (v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^ (v[5] >> 16) ^ v[5]
             ^ (v[6] << 16) ^ (v[6] >> 16) ^ (v[7] << 16);
         sx->hvec[5] = (v[0] << 16) ^ (v[0] & 0xffff0000) ^ (v[1] << 16) ^ (v[1] >> 16) ^ (v[1] & 0xffff0000) ^ (v[2] << 16) ^ v[2] ^ (v[3] >> 16) ^ v[3]
             ^ (v[4] << 16) ^ (v[4] >> 16) ^ v[4] ^ (v[5] << 16) ^ (v[6] << 16) ^ (v[6] >> 16) ^ v[6] ^ (v[7] << 16) ^ (v[7] >> 16) ^ (v[7] & 0xffff0000);
         sx->hvec[6] = v[0] ^ v[2] ^ (v[2] >> 16) ^ v[3] ^ (v[3] << 16) ^ v[4] ^ (v[4] >> 16)
             ^ (v[5] << 16) ^ (v[5] >> 16) ^ v[5] ^ (v[6] << 16) ^ (v[6] >> 16) ^ v[6] ^ (v[7] << 16) ^ v[7];
         sx->hvec[7] = v[0] ^ (v[0] >> 16) ^ (v[1] << 16) ^ (v[1] >> 16) ^ (v[2] << 16) ^ (v[3] >> 16) ^ v[3] ^ (v[4] << 16) ^ v[4] ^ (v[5] >> 16) ^ v[5]
             ^ (v[6] << 16) ^ (v[6] >> 16) ^ (v[7] << 16) ^ v[7];
}

/* ----------------------------------------------------------------------------------------------- */
/*! Основное циклическое преобразование (Этап 2)                                                   */
 static void ak_hash_gosthash94_update( ak_hash ctx, const ak_pointer in, const ak_uint64 size )
{
  ak_uint64 quot = 0, offset = 0;
  struct gosthash94_ctx *sx = NULL;

  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to a context" );
    return;
  }
  if( !size ) {
    ak_error_message( ak_error_zero_length, __func__ , "using zero length for hash data" );
    return;
  }
  quot = size/ctx->bsize;
  if( size - quot*ctx->bsize ) { /* длина данных должна быть кратна ctx->bsize */
    ak_error_message( ak_error_wrong_length, __func__ , "using data with wrong length" );
    return;
  }

  sx = ( struct gosthash94_ctx * ) ctx->data;
  do{
      sx->len[0] += 256;
      if( sx->len[0] < 256 ) sx->len[1]++; // увеличиваем длину сообщения

      ak_hash_gosthash94_addition( (ak_uint8 *) sx->sum, (ak_uint8 *)in + offset, 32 );
      ak_hash_gosthash94_compress( sx, (ak_uint32 *)in + (offset >> 2));
      offset += ctx->bsize;
    }
  while( offset < size );
}

/* ----------------------------------------------------------------------------------------------- */
 static void ak_hash_gosthash94_final( ak_hash ctx, const ak_pointer in, const ak_uint64 size )
{
  struct gosthash94_ctx *sx = NULL;

  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to a context" );
    return;
  }
  if( size >= 32 ) {
    ak_error_message( ak_error_zero_length, __func__ , "using zero length for hash data" );
    return;
  }

  sx = ( struct gosthash94_ctx * ) ctx->data;
  if( size > 0 ) {
    ak_uint32 ms[8];
    ak_uint32 bits = (ak_uint32 )( size << 3 );

    memset( ms, 0, 32 ); memcpy( ms, in, (size_t) size ); // копируем данные в вектор M'
    sx->len[0] += bits;
    if( sx->len[0] < bits) sx->len[1]++; // увеличиваем длину сообщения

    ak_hash_gosthash94_addition( (ak_uint8 *) sx->sum, (ak_uint8 *)ms, (const ak_uint32) size );
    ak_hash_gosthash94_compress( sx, ms );
  }
  ak_hash_gosthash94_compress( sx, sx->len );
  ak_hash_gosthash94_compress( sx, sx->sum );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает контекст алгоритма бесключевого хеширования, регламентируемого стандартом
    ГОСТ Р 34.11-94 (в настоящее время данный стандарт отменен).
    В качесте параметра алгоритма выступает OID (идентификатор) таблиц замен, используемых в
    алгоритме хеширования.

    @param oid Идентификатор, задающий таблицы замен, используемые в алгоритме ГОСТ Р 34.11-94
    @return Функция возвращает указатель на созданный контекст. В случае возникновения ошибки
    возвращается NULL, а код ошибки может быть получен с помощью вызова
    функции ak_error_get_value()                                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_hash ak_hash_new_gosthash94( ak_oid oid )
{
  ak_hash ctx = NULL;
  struct gosthash94_ctx *sx = NULL;

  if( oid == NULL ) {
     ak_error_message( ak_error_null_pointer, __func__ , "using a NULL pointer to OID" );
     return NULL;
  }
  if( oid->engine != hash_function ) {
      ak_error_message( ak_error_oid_engine, __func__ , "using a not hash function OID" );
      return NULL;
  }
  if( oid->mode != kbox_params ) {
      ak_error_message( ak_error_oid_mode, __func__ , "using a wrong mode OID" );
      return NULL;
  }

 /* создаем контекст */
  if(( ctx = ak_hash_new( sizeof( struct gosthash94_ctx ))) == NULL ) {
    ak_error_message( ak_error_create_function, __func__ , "incorrect context creation" );
    return NULL;
  }
  ctx->bsize = 32; /* длина блока обрабатываемых данных составляет 256 бит */
  ctx->hsize = 32; /* длина хешкода составляет 256 бит */

 /* устанавливаем таблицы замен, указатель на которые хранится в OID */
  sx = ( struct gosthash94_ctx *) ctx->data;
  ak_kbox_to_sbox( (const ak_kbox) oid->data, sx->k21, sx->k43, sx->k65, sx->k87 );

 /* устанавливаем OID алгоритма хеширования */
  if(( ctx->oid = ak_oids_find_by_name( "gosthash94" )) == NULL ) {
    ak_error_message( ak_error_find_pointer, __func__ , "incorrect search of gosthash94 OID" );
    return ctx = ak_hash_delete( ctx );
  }
  /* устанавливаем функции - обработчики событий */
  ctx->clean =  ak_hash_gosthash94_clean;
  ctx->code =   ak_hash_gosthash94_get_code;
  ctx->update = ak_hash_gosthash94_update;
  ctx->final =  ak_hash_gosthash94_final;
 return ctx;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Проверка корректной работы функции ГОСТ Р 34.11-94
     @return Если тестирование прошло успешно возвращается ak_true (истина). В противном случае,
     возвращается ak_false.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_hash_test_gosthash94( void )
{
 /* определяем тестовые значения */
  ak_uint8 test_text1[32] = {
   0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2c,
   0x20, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3d, 0x33, 0x32, 0x20, 0x62, 0x79, 0x74, 0x65, 0x73
  };
  ak_uint8 test_text2[50] = {
   0x53, 0x75, 0x70, 0x70, 0x6f, 0x73, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6f, 0x72, 0x69, 0x67,
   0x69, 0x6e, 0x61, 0x6c, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x68, 0x61, 0x73,
   0x20, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x20, 0x3d, 0x20, 0x35, 0x30, 0x20, 0x62, 0x79, 0x74,
   0x65, 0x73
  };
  ak_uint8 test_hash1[32] = {
   0xb1, 0xc4, 0x66, 0xd3, 0x75, 0x19, 0xb8, 0x2e, 0x83, 0x19, 0x81, 0x9f, 0xf3, 0x25, 0x95, 0xe0,
   0x47, 0xa2, 0x8c, 0xb6, 0xf8, 0x3e, 0xff, 0x1c, 0x69, 0x16, 0xa8, 0x15, 0xa6, 0x37, 0xff, 0xfa
  };
  ak_uint8 test_hash2[32] = {
   0x47, 0x1a, 0xba, 0x57, 0xa6, 0x0a, 0x77, 0x0d, 0x3a, 0x76, 0x13, 0x06, 0x35, 0xc1, 0xfb, 0xea,
   0x4e, 0xf1, 0x4d, 0xe5, 0x1f, 0x78, 0xb4, 0xae, 0x57, 0xdd, 0x89, 0x3b, 0x62, 0xf5, 0x52, 0x08
  };
  ak_uint8 test_VerbaO_1[32] = {
   0xb1, 0x85, 0xd2, 0x09, 0x31, 0x1d, 0xc0, 0x82, 0x54, 0x49, 0x90, 0x25, 0x63, 0x08, 0x3d, 0x2e,
   0x51, 0x1a, 0xb4, 0x7a, 0x8a, 0x2f, 0xaf, 0xe3, 0x88, 0xf2, 0xb4, 0xdf, 0x73, 0x81, 0x20, 0xe2
  };
  ak_uint8 test_VerbaO_2[32] = {
   0x0d, 0x26, 0x67, 0x96, 0xe6, 0x0d, 0x14, 0x67, 0xf5, 0xa1, 0x82, 0x5a, 0x41, 0xc7, 0x4d, 0x9a,
   0x60, 0x04, 0xe7, 0x94, 0xac, 0x8e, 0x29, 0x37, 0xc8, 0x2b, 0x46, 0x78, 0x5c, 0x15, 0xfc, 0xaf
  };

 /* определяем локальные переменные */
  ak_hash ctx = NULL;
  char *str = NULL;
  ak_bool result = ak_true;
  int audit = ak_log_get_level();
  ak_buffer rbuff = NULL, hbuff = NULL;

 /* первый пример из ГОСТ Р 34.11-94 */
  if((ctx = ak_hash_new_gosthash94( ak_oids_find_by_name( "id-gosthash94-TestParamSet" ))) == NULL ) {
      ak_error_message( ak_error_get_value(), __func__ , "wrong creation of hash function context" );
      result = ak_false;
      goto lab_exit;
  }
  result = ak_buffer_is_equal( rbuff = ak_hash_data( ctx, test_text1, 32, NULL ),
                                          hbuff = ak_buffer_new_ptr( test_hash1, 32, ak_false ));
                                    /* здесь false означает, что мы не выделяем память под буффер */
  if( result != ak_true ) {
     ak_error_message( ak_error_not_equal_data, __func__ ,
                                "the 1st test with id-gosthash94-TestParamSet is wrong" );
     ak_log_set_message(( str = ak_buffer_to_hexstr( hbuff ))); free( str );
     ak_log_set_message(( str = ak_buffer_to_hexstr( rbuff ))); free( str );
     goto lab_exit;
  }
  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "the 1st test with id-gosthash94-TestParamSet is Ok" );
  rbuff = ak_buffer_delete( rbuff );
  hbuff = ak_buffer_delete( hbuff );

  /* второй пример из ГОСТ Р 34.11-94 */
  result = ak_buffer_is_equal( rbuff = ak_hash_data( ctx, test_text2, 50, NULL ),
                                         hbuff = ak_buffer_new_ptr( test_hash2, 32, ak_false ));
  if( result != ak_true ) {
     ak_error_message( ak_error_not_equal_data, __func__ ,
                                "the 2nd test with id-gosthash94-TestParamSet is wrong" );
     ak_log_set_message(( str = ak_buffer_to_hexstr( hbuff ))); free( str );
     ak_log_set_message(( str = ak_buffer_to_hexstr( rbuff ))); free( str );
     goto lab_exit;
  }
  if( audit >= ak_log_maximum )
    ak_error_message( ak_error_ok, __func__ , "the 2nd test with id-gosthash94-TestParamSet is Ok" );
  ctx = ak_hash_delete( ctx );
  rbuff = ak_buffer_delete( rbuff );
  hbuff = ak_buffer_delete( hbuff );

 /* первый пример для таблиц замен из Верба-О */
  if((ctx = ak_hash_new_gosthash94( ak_oids_find_by_name( "id-gosthash94-VerbaO-ParamSet" ))) == NULL ) {
      ak_error_message( ak_error_get_value(), __func__ , "wrong creation of hash function context" );
      result = ak_false;
      goto lab_exit;
  }
  result = ak_buffer_is_equal( rbuff = ak_hash_data( ctx, test_text1, 32, NULL ),
                                          hbuff = ak_buffer_new_ptr( test_VerbaO_1, 32, ak_false ));
  if( result != ak_true ) {
     ak_error_message( ak_error_not_equal_data, __func__ ,
                             "the 1st test with id-gosthash94-VerbaO-ParamSet is wrong" );
     ak_log_set_message(( str = ak_buffer_to_hexstr( hbuff ))); free( str );
     ak_log_set_message(( str = ak_buffer_to_hexstr( rbuff ))); free( str );
     goto lab_exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                "the 1st test with id-gosthash94-VerbaO-ParamSet is Ok" );
  rbuff = ak_buffer_delete( rbuff );
  hbuff = ak_buffer_delete( hbuff );

 /* второй пример для таблиц замен из Верба-О */
  result = ak_buffer_is_equal( rbuff = ak_hash_data( ctx, test_text2, 50, NULL ),
                                         hbuff = ak_buffer_new_ptr( test_VerbaO_2, 32, ak_false ));
  if( result != ak_true ) {
     ak_error_message( ak_error_not_equal_data, __func__ ,
                             "the 2nd test with id-gosthash94-VerbaO-ParamSet is wrong" );
     ak_log_set_message(( str = ak_buffer_to_hexstr( hbuff ))); free( str );
     ak_log_set_message(( str = ak_buffer_to_hexstr( rbuff ))); free( str );
     goto lab_exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                "the 2nd test with id-gosthash94-VerbaO-ParamSet is Ok" );
  lab_exit:
   ctx = ak_hash_delete( ctx );
   rbuff = ak_buffer_delete( rbuff );
   hbuff = ak_buffer_delete( hbuff );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                  ak_gosthash.c  */
/* ----------------------------------------------------------------------------------------------- */
