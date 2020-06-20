/* Пример, иллюстрирующий скорость хеширования памяти.

   test-internal-hash04.c
*/

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
#ifndef _WIN32
 #include <unistd.h>
#endif
 #include <time.h>
 #include <ak_hash.h>
 #include <ak_parameters.h>
#ifdef __linux__
 #include <sys/resource.h>
#endif

 int main( void )
{
  clock_t timea;
  int i, error;
  struct hash ctx;
  ak_uint8 *data, out[64];
  size_t size = 0;
  double iter = 0, avg = 0;

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* статический объект существует, но он требует инициализации */
  if(( error = ak_hash_context_create_streebog512( &ctx )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect initialization of hash context" );
    return ak_libakrypt_destroy();
  }

  for( i = 16; i < 129; i += 8 ) {
    data = malloc( size = ( size_t ) i*1024*1024 );
    memset( data, (ak_uint8)i+1, size );

   /* теперь собственно хеширование памяти */
    timea = clock();
    ak_mac_context_ptr( &ctx.mctx, data, size, out, sizeof( out ));
    timea = clock() - timea;
    printf(" %3uMB: hash time: %fs, per 1MB = %fs, speed = %f MBs\n", (unsigned int)i,
               (double) timea / (double) CLOCKS_PER_SEC,
               (double) timea / ( (double) CLOCKS_PER_SEC*i ),
               (double) CLOCKS_PER_SEC*i / (double) timea );
    if( i > 16 ) {
      iter += 1;
      avg += (double) CLOCKS_PER_SEC*i / (double) timea;
    }
    free( data );
  }

  printf("average memory hashing speed: %f MByte/sec\n", avg/iter );
  ak_hash_context_destroy( &ctx );
 return ak_libakrypt_destroy();
}
