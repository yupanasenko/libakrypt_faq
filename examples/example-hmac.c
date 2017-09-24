#include <stdio.h>
#include <libakrypt.h>
#include <ak_hmac.h>

 int main( void )
{
 struct hmac_key hctx;
 ak_uint8 key[32], out[32];
 ak_uint8 data[13];
 char *str = NULL;

 /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) {
    return ak_libakrypt_destroy();
  }

  ak_hmac_key_create_streebog256( &hctx );
  memset( key, 0, 32 );
  ak_hmac_key_assign_ptr( &hctx, key, 32 );

  memset( data, 1, 13 );
  ak_hmac_key_ptr_context( &hctx, data, 13, out );
  printf("%s\n", str = ak_ptr_to_hexstr( out, 32, ak_false )); free( str );

  ak_hmac_key_destroy( &hctx );

 return ak_libakrypt_destroy();
}
