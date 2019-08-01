/* Тестовый пример для оценки скорости операции умножения в
   полях характеристики два
   Пример использует неэкспортируемые функции.

   test-internal-gf2n.c
*/

 #include <time.h>
 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
 #include <ak_gf2n.h>

 static ak_uint32 iteration_count = 100000;

 int gf64test( void )
{
  clock_t time;
  ak_uint32 i = 0;
  ak_uint64 alpha[1]  = { 0xffac13LL },
             beta[1]  = { 0xcca321aaa1LL },
             gamma[1] = { 0x0LL };
#ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64
  ak_uint64  delta[1] = { 0x0LL };
#endif

  time = clock();
  for( i = 0; i < iteration_count; i++ ) ak_gf64_mul_uint64( gamma, alpha, beta );
  time = clock() - time;
  printf(" GF(2^64):  ak_gf64_mul_uint64 time:    %f sec\n", (double)time / (double)CLOCKS_PER_SEC );

#ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64
  time = clock();
  for( i = 0; i < iteration_count; i++ ) ak_gf64_mul_pcmulqdq( delta, alpha, beta );
  time = clock() - time;
  printf(" GF(2^64):  ak_gf64_mul_pcmulqdq time:  %f sec\n", (double)time / (double)CLOCKS_PER_SEC );

  if( ak_ptr_is_equal( gamma, delta, sizeof( gamma )) != ak_true ) return EXIT_FAILURE;
#endif
 return EXIT_SUCCESS;
}

 int gf128test( void )
{
  clock_t time;
  ak_uint32 i = 0;
  ak_uint64 alpha[2]  = { 0xffac13LL, 0x21ff670caLL },
             beta[2]  = { 0xcca321aaa1LL, 0x171817aacff32LL },
             gamma[2] = { 0x0LL, 0x0LL };
#ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64
  ak_uint64  delta[2] = { 0x0LL, 0x0LL };
#endif

  time = clock();
  for( i = 0; i < iteration_count; i++ ) ak_gf128_mul_uint64( gamma, alpha, beta );
  time = clock() - time;
  printf(" GF(2^128): ak_gf128_mul_uint64 time:   %f sec\n", (double)time / (double)CLOCKS_PER_SEC );

#ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64
  time = clock();
  for( i = 0; i < iteration_count; i++ ) ak_gf128_mul_pcmulqdq( delta, alpha, beta );
  time = clock() - time;
  printf(" GF(2^128): ak_gf128_mul_pcmulqdq time: %f sec\n", (double)time / (double)CLOCKS_PER_SEC );

  if( ak_ptr_is_equal( gamma, delta, sizeof( gamma )) != ak_true ) return EXIT_FAILURE;
#endif
 return EXIT_SUCCESS;
}


 int gf256test( void )
{
  clock_t time;
  ak_uint32 i = 0;
  ak_uint64 alpha[4]  = { 0xffac13LL, 0x21ff670caLL, 0x1ac678901acLL, 0xffff5436271cLL },
             beta[4]  = { 0xcca321aaa1LL, 0x171817aacff32LL, 0xcadfe4309888acLL, 0x1212111220dLL },
             gamma[4] = { 0x0LL, 0x0LL, 0x0LL, 0x0LL };
#ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64
  ak_uint64  delta[4] = { 0x0LL, 0x0LL, 0x0LL, 0x0LL };
#endif

  time = clock();
  for( i = 0; i < iteration_count; i++ ) ak_gf256_mul_uint64( gamma, alpha, beta );
  time = clock() - time;
  printf(" GF(2^256): ak_gf256_mul_uint64 time:   %f sec\n", (double)time / (double)CLOCKS_PER_SEC );

#ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64
  time = clock();
  for( i = 0; i < iteration_count; i++ ) ak_gf256_mul_pcmulqdq( delta, alpha, beta );
  time = clock() - time;
  printf(" GF(2^256): ak_gf256_mul_pcmulqdq time: %f sec\n", (double)time / (double)CLOCKS_PER_SEC );

  if( ak_ptr_is_equal( gamma, delta, sizeof( gamma )) != ak_true ) return EXIT_FAILURE;
#endif
 return EXIT_SUCCESS;
}

 int gf512test( void )
{
  clock_t time;
  ak_uint32 i = 0;
  ak_uint64 alpha[8]  = { 0xffac13LL, 0x21ff670caLL, 0x1ac678901acLL, 0xffff5436271cLL,
                          0x11adc75875LL, 0x121111fffffLL, 0xFFFFFFFFFFFFFFFLL, 0xFFFFFFFFea12LL },
             beta[8]  = { 0xcca321aaa1LL, 0x171817aacff32LL, 0xcadfe4309888acLL, 0x1212111220dLL,
                          0xaaaaa1211211LL, 0x98172aaaLL, 0x3438478347aaacLL, 0x12124cdeaf421aLL },
             gamma[8] = { 0x0LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL };
#ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64
  ak_uint64  delta[8] = { 0x0LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL, 0x0LL };
#endif

  time = clock();
  for( i = 0; i < iteration_count; i++ ) ak_gf512_mul_uint64( gamma, alpha, beta );
  time = clock() - time;
  printf(" GF(2^512): ak_gf512_mul_uint64 time:   %f sec\n", (double)time / (double)CLOCKS_PER_SEC );

#ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64
  time = clock();
  for( i = 0; i < iteration_count; i++ ) ak_gf512_mul_pcmulqdq( delta, alpha, beta );
  time = clock() - time;
  printf(" GF(2^512): ak_gf512_mul_pcmulqdq time: %f sec\n", (double)time / (double)CLOCKS_PER_SEC );

  if( ak_ptr_is_equal( gamma, delta, sizeof( gamma )) != ak_true ) return EXIT_FAILURE;
#endif
 return EXIT_SUCCESS;
}

 int main( void )
{
  if( gf64test() != EXIT_SUCCESS ) return EXIT_FAILURE;
  if( gf128test() != EXIT_SUCCESS ) return EXIT_FAILURE;
  if( gf256test() != EXIT_SUCCESS ) return EXIT_FAILURE;
  if( gf512test() != EXIT_SUCCESS ) return EXIT_FAILURE;

 return EXIT_SUCCESS;
}

