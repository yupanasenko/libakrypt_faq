/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_gf2n.c                                                                                 */
/*  - содержит реализацию функций умножения элементов конечных полей характеристики 2.             */
/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_STRING_H
 #include <string.h>
#else
 #error Library cannot be compiled without string.h header
#endif
#ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64
 #include <wmmintrin.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_gf2n.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию умножения двух элементов конечного поля \f$ \mathbb F_{2^{64}}\f$,
    порожденного неприводимым многочленом
    \f$ f(x) = x^{64} + x^4 + x^3 + x + 1 \in \mathbb F_2[x]\f$. Для умножения используется
    простейшая реализация, основанная на приведении по модулю после каждого шага алгоритма.        */
/* ----------------------------------------------------------------------------------------------- */
 void ak_gf64_mul_uint64( ak_pointer z, ak_pointer x, ak_pointer y )
{
 int i = 0;
 ak_uint64 zv = 0, n1,
#ifdef LIBAKRYPT_LITTLE_ENDIAN
   t = ((ak_uint64 *)y)[0], s = ((ak_uint64 *)x)[0];
#else
   t = bswap_64( ((ak_uint64 *)y)[0] ), s = bswap_64( ((ak_uint64 *)x)[0] );
#endif
 for( i = 0; i < 64; i++ ) {

   if( t&0x1 ) zv ^= s;
   t >>= 1;
   n1 = s&0x8000000000000000LL;
   s <<= 1;
   if( n1 ) s ^= 0x1B;
 }
#ifdef LIBAKRYPT_LITTLE_ENDIAN
 ((ak_uint64 *)z)[0] = zv;
#else
 ((ak_uint64 *)z)[0] = bswap_64(zv);
#endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию умножения двух элементов конечного поля \f$ \mathbb F_{2^{128}}\f$,
    порожденного неприводимым многочленом
    \f$ f(x) = x^{128} + x^7 + x^2 + x + 1 \in \mathbb F_2[x]\f$. Для умножения используется
    простейшая реализация, основанная на приведении по модулю после каждого шага алгоритма.        */
/* ----------------------------------------------------------------------------------------------- */
 void ak_gf128_mul_uint64( ak_pointer z, ak_pointer x, ak_pointer y )
{
 int i = 0;
 ak_uint64 t,
#ifdef LIBAKRYPT_LITTLE_ENDIAN
  s0 = ((ak_uint64 *)x)[0], s1 = ((ak_uint64 *)x)[1];
#else
  s0 = bswap_64( ((ak_uint64 *)x)[0] ), s1 = bswap_64( ((ak_uint64 *)x)[1] );
#endif

 /* обнуляем результирующее значение */
 ((ak_uint64 *)z)[0] = 0; ((ak_uint64 *)z)[1] = 0;

 /* вычисляем  произведение для младшей половины */
#ifdef LIBAKRYPT_LITTLE_ENDIAN
  t = ((ak_uint64 *)y)[0];
#else
  t = bswap_64( ((ak_uint64 *)y)[0] );
#endif
 for( i = 0; i < 64; i++ ) {
   if( t&0x1 ) { ((ak_uint64 *)z)[0] ^= s0; ((ak_uint64 *)z)[1] ^= s1; }
   t >>= 1;
   ak_gf128_mul_theta( s1, s0 );
 }

 /* вычисляем  произведение для старшей половины */
#ifdef LIBAKRYPT_LITTLE_ENDIAN
  t = ((ak_uint64 *)y)[1];
#else
  t = bswap_64( ((ak_uint64 *)y)[1] );
#endif

 for( i = 0; i < 63; i++ ) {

   if( t&0x1 ) { ((ak_uint64 *)z)[0] ^= s0; ((ak_uint64 *)z)[1] ^= s1; }
   t >>= 1;
   ak_gf128_mul_theta( s1, s0 );
 }

 if( t&0x1 ) {
   ((ak_uint64 *)z)[0] ^= s0;
   ((ak_uint64 *)z)[1] ^= s1;
 }
#ifdef LIBAKRYPT_BIG_ENDIAN
   ((ak_uint64 *)z)[0] = bswap_64( ((ak_uint64 *)z)[0] );
   ((ak_uint64 *)z)[1] = bswap_64( ((ak_uint64 *)z)[1] );
#endif
}

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию умножения двух элементов конечного поля \f$ \mathbb F_{2^{64}}\f$,
    порожденного неприводимым многочленом
    \f$ f(x) = x^{64} + x^4 + x^3 + x + 1 \in \mathbb F_2[x]\f$. Для умножения используется
    реализация с помощью команды PCLMULQDQ.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 void ak_gf64_mul_pcmulqdq( ak_pointer z, ak_pointer x, ak_pointer y )
{
#ifdef _MSC_VER
	 __m128i gm, xm, ym, cm, cx;

	 gm.m128i_u64[0] = 0x1B; gm.m128i_u64[1] = 0;
	 xm.m128i_u64[0] = ((ak_uint64 *)x)[0]; xm.m128i_u64[1] = 0;
	 ym.m128i_u64[0] = ((ak_uint64 *)y)[0]; ym.m128i_u64[1] = 0;

	 cm = _mm_clmulepi64_si128(xm, ym, 0x00);
	 cx.m128i_u64[0] = cm.m128i_u64[1]; cx.m128i_u64[1] = 0;

	 xm = _mm_clmulepi64_si128(cx, gm, 0x00);
	 xm.m128i_u64[1] ^= cx.m128i_u64[0];
	 ym.m128i_u64[0] = xm.m128i_u64[1]; ym.m128i_u64[1] = 0;
	 xm = _mm_clmulepi64_si128(ym, gm, 0x00);

	 ((ak_uint64 *)z)[0] = cm.m128i_u64[0] ^ xm.m128i_u64[0];
#else
  const __m128i gm = _mm_set_epi64x( 0, 0x1B );
  __m128i xm = _mm_set_epi64x( 0, ((ak_uint64 *)x)[0] );
  __m128i ym = _mm_set_epi64x( 0, ((ak_uint64 *)y)[0] );

  __m128i cm = _mm_clmulepi64_si128( xm, ym, 0x00 );
  __m128i cx = _mm_set_epi64x( 0, cm[1] );
  
  xm = _mm_clmulepi64_si128( cx, gm, 0x00 ); xm[1] ^= cx[0];
  ym = _mm_set_epi64x( 0, xm[1] );  
  xm = _mm_clmulepi64_si128( ym, gm, 0x00 );

  ((ak_uint64 *)z)[0] = cm[0]^xm[0];
 #endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию умножения двух элементов конечного поля \f$ \mathbb F_{2^{128}}\f$,
    порожденного неприводимым многочленом
    \f$ f(x) = x^{128} + x^7 + x^2 + x + 1 \in \mathbb F_2[x]\f$. Для умножения используется
    реализация с помощью команды PCLMULQDQ.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 void ak_gf128_mul_pcmulqdq( ak_pointer z, ak_pointer a, ak_pointer b )
{
#ifdef _MSC_VER
	 __m128i am, bm, cm, dm, em, fm;
	 ak_uint64 x3, D;

	 am.m128i_u64[0] = ((ak_uint64 *)a)[0];  am.m128i_u64[1] = ((ak_uint64 *)a)[1];
	 bm.m128i_u64[0] = ((ak_uint64 *)b)[0];  bm.m128i_u64[1] = ((ak_uint64 *)b)[1];

	 /* умножение */
	 cm = _mm_clmulepi64_si128(am, bm, 0x00); // c = a0*b0
	 dm = _mm_clmulepi64_si128(am, bm, 0x11); // d = a1*b1
	 em = _mm_clmulepi64_si128(am, bm, 0x10); // e = a0*b1
	 fm = _mm_clmulepi64_si128(am, bm, 0x01); // f = a1*b0

	/* приведение */
	 x3 = dm.m128i_u64[1];
	 D = dm.m128i_u64[0] ^ em.m128i_u64[1] ^ fm.m128i_u64[1] ^ (x3 >> 63) ^ (x3 >> 62) ^ (x3 >> 57);

	 cm.m128i_u64[0] ^= D ^ (D << 1) ^ (D << 2) ^ (D << 7);
	 cm.m128i_u64[1] ^= em.m128i_u64[0] ^ fm.m128i_u64[0] ^ x3 ^ (x3 << 1) ^ (D >> 63) ^ (x3 << 2) ^ (D >> 62) ^ (x3 << 7) ^ (D >> 57);

	 ((ak_uint64 *)z)[0] = cm.m128i_u64[0];
	 ((ak_uint64 *)z)[1] = cm.m128i_u64[1];
#else
	 __m128i am = _mm_set_epi64x(((ak_uint64 *)a)[1], ((ak_uint64 *)a)[0]);
	 __m128i bm = _mm_set_epi64x(((ak_uint64 *)b)[1], ((ak_uint64 *)b)[0]);

	 /* умножение */
	 __m128i cm = _mm_clmulepi64_si128(am, bm, 0x00); // c = a0*b0
	 __m128i dm = _mm_clmulepi64_si128(am, bm, 0x11); // d = a1*b1
	 __m128i em = _mm_clmulepi64_si128(am, bm, 0x10); // e = a0*b1
	 __m128i fm = _mm_clmulepi64_si128(am, bm, 0x01); // f = a1*b0

	 /* приведение */
	 ak_uint64 x3 = dm[1];
	 ak_uint64 D = dm[0] ^ em[1] ^ fm[1] ^ (x3 >> 63) ^ (x3 >> 62) ^ (x3 >> 57);

	 cm[0] ^= D ^ (D << 1) ^ (D << 2) ^ (D << 7);
	 cm[1] ^= em[0] ^ fm[0] ^ x3 ^ (x3 << 1) ^ (D >> 63) ^ (x3 << 2) ^ (D >> 62) ^ (x3 << 7) ^ (D >> 57);

	 ((ak_uint64 *)z)[0] = cm[0];
	 ((ak_uint64 *)z)[1] = cm[1];
#endif
}
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тестирование операции умножения в поле \f$ \mathbb F_{2^{64}}\f$. */
 static bool_t ak_gf64_multiplication_test( void )
{
 int i = 0;
 char out[128];
 ak_uint8 values8[64] = { /* последовательный набор байт в памяти */
    0x61, 0x30, 0xD1, 0xDE, 0x01, 0x73, 0x01, 0x30, 0x11, 0x0E, 0x1F, 0xE9, 0xA3, 0x06, 0x1C, 0x6B,
    0x14, 0x1A, 0xD5, 0x69, 0xFE, 0xF4, 0xA8, 0x26, 0x03, 0xCA, 0x3F, 0x74, 0x0C, 0x2F, 0x3A, 0x97,
    0x3F, 0x3D, 0x85, 0x40, 0xED, 0x56, 0x5C, 0x89, 0xCE, 0x5E, 0x5E, 0xC6, 0x29, 0x02, 0x34, 0xAE,
    0xE2, 0x8C, 0xA1, 0x03, 0xDE, 0xDB, 0x71, 0xFE, 0x52, 0x5E, 0xBD, 0xBB, 0x63, 0x1C, 0xE6, 0x18 };
 ak_uint64 values[8] =
#ifdef LIBAKRYPT_LITTLE_ENDIAN
  {
    0x30017301ded13061LL, 0x6b1c06a3e91f0e11LL, 0x26a8f4fe69d51a14LL, 0x973a2f0c743fca03LL,
    0x895c56ed40853d3fLL, 0xae340229c65e5eceLL, 0xfe71dbde03a18ce2LL, 0x18e61c63bbbd5e52LL };
#else
  {
    0x6130D1DE01730130LL, 0x110E1FE9A3061C6BLL, 0x141AD569FEF4A826LL, 0x03CA3F740C2F3A97LL,
    0x3F3D8540ED565C89LL, 0xCE5E5EC6290234AELL, 0xE28CA103DEDB71FELL, 0x525EBDBB631CE618LL };
#endif
 ak_uint64 x, y, z = 0, z1 = 0;

 /* сравниваем исходные данные */
  for( i = 0; i < 8; i++ ) {
    if( !ak_ptr_is_equal( values8+i*8, &values[i], 8 )) {
      ak_error_message_fmt( ak_error_not_equal_data, __func__,
                                        "wrong constant V[%d] in memory representation", i );
      return ak_false;
    }
  }

 /* сравнение с контрольными примерами */
#ifdef LIBAKRYPT_LITTLE_ENDIAN
  y = 0xF000000000000011LL; x = 0x00001aaabcda1115LL;
#else
  y = 0x11000000000000F0LL; x = 0x1511dabcaa1a0000LL;
#endif
 (void)z1; /* неиспользуемая переменная */

 for( i = 0; i < 8; i++ ) {
    ak_gf64_mul_uint64( &z, &x, &y );
    if( z != values[i] ) {
      ak_ptr_to_hexstr_static( &z, 8, out, 128, ak_true );
      ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                            "uint64 calculated %s on iteration %d", out, i );
      ak_ptr_to_hexstr_static( &values[i], 8, out, 128, ak_true );
      ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                            "uint64 expected   %s on iteration %d", out, i );
      return ak_false;
    }
    x = y; y = z;
  }

#ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64
 if( ak_log_get_level() >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__, "comparison between two implementations included");

 /* сравнение с контрольными примерами */
 y = 0xF000000000000011LL; x = 0x1aaabcda1115LL; z = 0;
 for( i = 0; i < 8; i++ ) {
    ak_gf64_mul_pcmulqdq( &z, &x, &y );
    if( z != values[i] ) {
      ak_ptr_to_hexstr_static( &z, 8, out, 128, ak_true );
      ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                           "pcmulqdq calculated %s on iteration %d", out, i );
      ak_ptr_to_hexstr_static( &values[i], 8, out, 128, ak_true );
      ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                           "pcmulqdq expected   %s on iteration %d", out, i );
      return ak_false;
    }
    x = y; y = z;
  }

 /* проверка идентичности работы двух реализаций */
 y = 0xF1abcd5421110011LL; x = 0x1aaabcda1115LL; z = 0;
 for( i = 0; i < 1000; i++ ) {
    ak_gf64_mul_uint64( &z, &x, &y );
    ak_gf64_mul_pcmulqdq( &z1, &x, &y );
    if( z != z1 ) {
      ak_ptr_to_hexstr_static( &z, 8, out, 128, ak_true );
      ak_error_message_fmt( ak_error_not_equal_data, __func__ , "uint64 calculated   %s", out );
      ak_ptr_to_hexstr_static( &z1, 8, out, 128, ak_true );
      ak_error_message_fmt( ak_error_not_equal_data, __func__ , "pcmulqdq calculated %s", out );
      return ak_false;
    }
    x = y; y = z;
  }
 if( ak_log_get_level() >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__, "one thousand iterations for random values is Ok");
#endif
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тестирование операции умножения в поле \f$ \mathbb F_{2^{128}}\f$. */
 static bool_t ak_gf128_multiplication_test( void )
{
 int i = 0;
 char out[128];

 ak_uint8 a8[16] = {
      0x5d, 0x47, 0x53, 0x5d, 0x72, 0x6f, 0x74, 0x63, 0x65, 0x56, 0x74, 0x73, 0x65, 0x54, 0x5b, 0x7b };
 ak_uint8 b8[16] = {
      0x5d, 0x6e, 0x6f, 0x72, 0x65, 0x75, 0x47, 0x5b, 0x29, 0x79, 0x61, 0x68, 0x53, 0x28, 0x69, 0x48 };
 ak_uint8 m8[16] = {
      0xd2, 0x06, 0x35, 0x32, 0xda, 0x10, 0x4e, 0x7e, 0x2e, 0xd1, 0x5e, 0x9a, 0xa0, 0x29, 0x02, 0x04 };
 ak_uint8 result[16], result2[16];

 ak_uint128 a, b, m;
#ifdef LIBAKRYPT_LITTLE_ENDIAN
  a.q[0] = 0x63746f725d53475dLL; a.q[1] = 0x7b5b546573745665LL;
  b.q[0] = 0x5b477565726f6e5dLL; b.q[1] = 0x4869285368617929LL;
  m.q[0] = 0x7e4e10da323506d2LL; m.q[1] = 0x040229a09a5ed12eLL;
#else
  a.q[0] = 0x5d47535d726f7463LL; a.q[1] = 0x6556747365545b7bLL;
  b.q[0] = 0x5d6e6f726575475bLL; b.q[1] = 0x2979616853286948LL;
  m.q[0] = 0xd2063532da104e7eLL; m.q[1] = 0x2ed15e9aa0290204LL;
#endif
  memset( result, 0, 16 );
  memset( result2, 0, 16 );
  (void)i;

 /* сравниваем данные */
 if( !ak_ptr_is_equal( a8, a.q, 16 )) {
   ak_error_message( ak_error_not_equal_data, __func__, "wrong constant A in memory representation");
   return ak_false;
 }
 if( !ak_ptr_is_equal( b8, b.q, 16 )) {
   ak_error_message( ak_error_not_equal_data, __func__, "wrong constant B in memory representation");
   return ak_false;
 }
 if( !ak_ptr_is_equal( m8, m.q, 16 )) {
   ak_error_message( ak_error_not_equal_data, __func__, "wrong constant M in memory representation");
   return ak_false;
 }

 /* проверяем пример из white paper для GCM (применение pcmulqdq для GCM)
    a = 0x7b5b54657374566563746f725d53475d
    b = 0x48692853686179295b477565726f6e5d
    GFMUL128 (a, b) = 0x40229a09a5ed12e7e4e10da323506d2 */

 ak_gf128_mul_uint64( result, &a, &b );
 if( !ak_ptr_is_equal( result, m8, 16 )) {
   ak_ptr_to_hexstr_static( result, 16, out, 128, ak_true );
   ak_error_message_fmt( ak_error_not_equal_data, __func__ , "calculated %s", out );
   ak_ptr_to_hexstr_static( m8, 16, out, 128, ak_true );
   ak_error_message_fmt( ak_error_not_equal_data, __func__ , "expected   %s", out );
   return ak_false;
 }

#ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64
 if( ak_log_get_level() >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__, "comparison between two implementations included");

 ak_gf128_mul_pcmulqdq( result2, &a, &b );
 /* сравнение с константой */
 if( !ak_ptr_is_equal( result2, m8, 16 )) {
   ak_ptr_to_hexstr_static( result2, 16, out, 128, ak_true );
   ak_error_message_fmt( ak_error_not_equal_data, __func__ , "pcmulqdq calculated %s", out );
   ak_ptr_to_hexstr_static( m8, 16, out, 128, ak_true );
   ak_error_message_fmt( ak_error_not_equal_data, __func__ , "pcmulqdq expected   %s", out );
   return ak_false;
 }
 /* сравнение с другим способом вычисления */
 if( !ak_ptr_is_equal( result2, result, 16 )) {
   ak_ptr_to_hexstr_static( result2, 16, out, 128, ak_true );
   ak_error_message_fmt( ak_error_not_equal_data, __func__ , "pcmulqdq calculated %s", out );
   ak_ptr_to_hexstr_static( result, 16, out, 128, ak_true );
   ak_error_message_fmt( ak_error_not_equal_data, __func__ , "uint64 calculated   %s", out );
   return ak_false;
 }

 /* сравнение для двух способов на нескольких значениях */
 for( i = 1; i < 1000; i++ ) {
   a.q[0] = b.q[1]; a.q[1] = b.q[0];
   memcpy( b.b, result, 16 );

   ak_gf128_mul_uint64( result, &a, &b );
   ak_gf128_mul_pcmulqdq( result2, &a, &b );
   if( !ak_ptr_is_equal( result, result2, 16 )) {
     ak_ptr_to_hexstr_static( result2, 16, out, 128, ak_true );
     ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                          "pcmulqdq calculated %s on iteration %d", out, i );
     ak_ptr_to_hexstr_static( result, 16, out, 128, ak_true );
     ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                            "uint64 calculated %s on iteration %d", out, i );
     return ak_false;
   }
 }
 if( ak_log_get_level() >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__, "one thousand iterations for random values is Ok");
#endif
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_gfn_multiplication_test( void )
{
 int audit = ak_log_get_level();

 if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing the Galois fileds arithmetic started");

#ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64
 if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ ,
                                       "using pcmulqdq for multiplication in finite Galois fields");
#endif

 if( ak_gf64_multiplication_test( ) != ak_true ) {
   ak_error_message( ak_error_get_value(), __func__ , "incorrect multiplication test in GF(2^64)");
   return ak_false;
 } else
    if( audit >= ak_log_maximum )
     ak_error_message( ak_error_get_value(), __func__ , "multiplication test in GF(2^64) is OK");

 if( ak_gf128_multiplication_test( ) != ak_true ) {
   ak_error_message( ak_error_get_value(), __func__ , "incorrect multiplication test in GF(2^128)");
   return ak_false;
 } else
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_get_value(), __func__ , "multiplication test in GF(2^128) is OK");

 if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ ,
                                         "testing the Galois fileds arithmetic ended successfully");
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_gf2n.c  */
/* ----------------------------------------------------------------------------------------------- */
