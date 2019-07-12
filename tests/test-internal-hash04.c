/* Пример, иллюстрирующий скорость хеширования памяти.

   test-internal-hash04.c
*/

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <time.h>
 #include <ak_hash.h>
 #include <ak_parameters.h>

 int main( void )
{
  clock_t time;
  int i, error, mbsize = 64;
  struct hash ctx;
  ak_uint8 data[1024], out[64];


 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* статический объект существует, но он требует инициализации */
  if(( error = ak_hash_context_create_streebog512( &ctx )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect initialization of hash context" );
    return ak_libakrypt_destroy();
  }

 /* теперь собственно зашифрование */
  memset( data, 0x13, sizeof( data ));
  time = clock();
  ctx.clean( &ctx );
  for( i = 0; i < 1024*mbsize; i++ ) {
     ctx.update( &ctx, data, sizeof( data ));
  }
  ctx.finalize( &ctx, NULL, 0, out );
  time = clock() - time;
  printf(" hash time: %fs, per 1MB = %fs, speed = %f MBs\n",
               (double) time / (double) CLOCKS_PER_SEC,
               (double) time / ( (double) CLOCKS_PER_SEC * mbsize ), (double) CLOCKS_PER_SEC *mbsize / (double) time );

 return ak_libakrypt_destroy();
}
