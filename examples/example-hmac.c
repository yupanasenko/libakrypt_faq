#include <stdio.h>
#include <libakrypt.h>

 int main( void )
{
 ak_uint8 out[64];
 char *str = NULL;
 size_t size = 64;
 char password[64];
 int error = ak_error_ok;
 ak_uint8 data[15] = "this is my data";
 ak_handle handle = ak_error_wrong_handle;

 /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
    return ak_libakrypt_destroy();

 /* создаем дескриптор ключа выработки имитовставки */
  if(( handle = ak_hmac_new_streebog256( "my new hmac key" )) == ak_error_wrong_handle )
    return ak_libakrypt_destroy();
  printf("created %s engine handle\n", ak_handle_get_engine_str( handle ));

 /* ожидаемый размер имитовставки */
  printf("expected integrity code size: %d bytes\n", (int) ak_hmac_get_icode_size( handle ));

 /* тест первый: вырабатываем случайный ключ и вычисляем имитовставку */
  printf("generation of secret key... "); fflush( stdout );
  if(( error = ak_hmac_set_key_random( handle )) != ak_error_ok )
    ak_error_message( error, __func__, "wrong generation of random secret hmac key" );
  else printf("Ok\n");

  ak_hmac_ptr( handle, data, sizeof( data ), out );
  if(( error = ak_error_get_value()) != ak_error_ok )
    ak_error_message( error, __func__, "wrong calculation of hmac integrity code" );

  printf("hmac: %s\n",
   str = ak_ptr_to_hexstr( out, ak_hmac_get_icode_size( handle ), ak_false )); free( str );

 /* тест второй: вырабатываем ключ из пароля и снова вычисляем имитовставку */
  printf("input a password: ");
  ak_password_read( password, size );
  printf("[password: %s (max size: %u, strlen: %u)]\n",
                         password, (unsigned int) size, (unsigned int) strlen( password ));
  ak_hmac_set_key_password( handle, password, strlen( password ), "random initial value", 20 );

  ak_hmac_ptr( handle, data, sizeof( data ), out );
  if(( error = ak_error_get_value()) != ak_error_ok )
    ak_error_message( error, __func__, "wrong calculation of hmac integrity code" );

  printf("hmac: %s\n",
   str = ak_ptr_to_hexstr( out, ak_hmac_get_icode_size( handle ), ak_false )); free( str );

 return ak_libakrypt_destroy();
}
