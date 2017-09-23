#include <stdio.h>
#include <libakrypt.h>
#include <ak_hmac.h>

 int main( void )
{
 struct hmac_key hctx;


 /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) {
    return ak_libakrypt_destroy();
  }

  ak_hmac_key_create_streebog256( &hctx );
  ak_hmac_key_destroy( &hctx );

 return ak_libakrypt_destroy();
}
