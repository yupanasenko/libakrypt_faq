#include <stdio.h>
#include <libakrypt.h>
#include <ak_hmac.h>

 int main( void )
{
 struct hmac hctx;
 ak_uint8 out[32];
 ak_uint8 data[13];
 char *str = NULL;
 ak_uint64 seed = 12345678;

 /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) {
    return ak_libakrypt_destroy();
  }

  ak_hmac_create_streebog256( &hctx );
  hctx.key.generator.randomize_ptr( &hctx.key.generator, &seed, sizeof( seed ));
  ak_hmac_set_random(  &hctx, &hctx.key.generator );

  memset( data, 1, 13 );
  ak_hmac_ptr_context( &hctx, data, 13, out );
  printf("%s\n", str = ak_ptr_to_hexstr( out, 32, ak_false )); free( str );

  ak_hmac_destroy( &hctx );

 return ak_libakrypt_destroy();
}
