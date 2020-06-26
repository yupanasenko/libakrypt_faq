/* Пример, иллюстрирующий скорость шифрования памяти.

   test-internal-bckey04.c
*/

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
#ifndef _WIN32
 #include <unistd.h>
#endif
 #include <time.h>
 #include <ak_bckey.h>
 #include <ak_parameters.h>

 /* значение секретного ключа согласно ГОСТ Р 34.12-2015 */
  ak_uint8 key[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88
  };
  ak_uint8 iv[16] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0,
                     0xfa, 0xaa, 0x31, 0xe2, 0x00, 0xe1, 0xae, 0x1a };

 typedef int ( efunction )( ak_bckey , ak_pointer , ak_pointer , size_t , ak_pointer , size_t );
 void test( char *, efunction *, ak_bckey );

 int main( void )
{
  struct bckey ctx;

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* статический объект существует, но он требует инициализации */
  printf("key create: %d\n", ak_bckey_context_create_kuznechik( &ctx ));
  printf("key set value: %d\n", ak_bckey_context_set_key( &ctx, key, sizeof( key )));

  test( "CFB", ak_bckey_context_cfb, &ctx );
  test( "OFB", ak_bckey_context_ofb, &ctx );
  test( "CBC", ak_bckey_context_encrypt_cbc, &ctx );
  test( "CTR", ak_bckey_context_ctr, &ctx );

  ak_bckey_context_destroy( &ctx );
 return ak_libakrypt_destroy();
}

/* -------------------------------------------------------------------------------------- */
 void test( char *STR, efunction fun, ak_bckey ctx )
{
  int i;
  clock_t timea;
  ak_uint8 *data;
  size_t size;
  double iter = 0, avg = 0;

  for( i = 16; i < 129; i += 8 ) {
    data = malloc( size = ( size_t ) i*1024*1024 );
    memset( data, (ak_uint8)i+1, size );
    ctx->key.resource.value.counter = size; /* на очень больших объемах одного ключа мало */
    timea = clock();
    fun( ctx, data, data, size, iv, sizeof( iv ));
    timea = clock() - timea;
    printf(" %3uMB: %s time: %fs, per 1MB = %fs, speed = %f MBs\n", (unsigned int)i, STR,
               (double) timea / (double) CLOCKS_PER_SEC,
               (double) timea / ( (double) CLOCKS_PER_SEC*i ),
               (double) CLOCKS_PER_SEC*i / (double) timea );
    if( i > 16 ) {
      iter += 1;
      avg += (double) CLOCKS_PER_SEC*i / (double) timea;
    }
    free( data );
  }
  printf("average memory %s speed: %f MByte/sec\n\n", STR, avg/iter );

}
