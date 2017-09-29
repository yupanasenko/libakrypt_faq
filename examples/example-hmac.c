#include <stdio.h>
#include <libakrypt.h>

 int main( void )
{
 size_t size = 64;
 char password[64];
 ak_uint8 data[15] = "this is my data";
 ak_handle handle = ak_error_wrong_handle;

 /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
    return ak_libakrypt_destroy();

 /* создаем дескриптор ключа выработки имитовставки */
  if(( handle = ak_hmac_new_streebog256( "my new hmac key" )) == ak_error_wrong_handle )
    return ak_libakrypt_destroy();

 /* ожидаемый размер имитовставки */
  printf("expected integrity code size: %d bytes\n", (int) ak_hmac_get_icode_size( handle ));

 /* инициализируем ключ выработанным из пароля значением */
  printf("input a password: ");
  ak_password_read( password, size );
  printf("[password: %s (max size: %u, strlen: %u)]\n",
                            password, (unsigned int) size, (unsigned int) strlen(password) );
  ak_hmac_set_password( handle, password, strlen(password), "random initial value", 20 );

 /* вычисляем имитовставку */

 return ak_libakrypt_destroy();
}
