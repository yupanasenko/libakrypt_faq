 #include <stdio.h>
 #include <libakrypt.h>

 int main( void )
{
  char *str = NULL;
 /* определяем дескриптор и инициализируем его */
  ak_handle handle = ak_error_wrong_handle;
 /* определяем данные для хэширования */
  ak_uint8 data[44] = "The quick brown fox jumps over the lazy dog\0";

 /* буффер для хранения результата */
  ak_buffer buffer = NULL;

 /* инициализируем библиотеку */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
    return ak_libakrypt_destroy();

 /* создаем дескриптор функции хеширования */
  if(( handle = ak_hash_new_streebog256()) == ak_error_wrong_handle ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong descriptor creation");
    return ak_libakrypt_destroy();
  }

 /* ожидаемый размер хэш-кода */
  printf("expected code size: %d bytes\n", (int) ak_hash_get_icode_size( handle ));

 /* вычисление хэш-кода */
  printf("data: %s\n", data );
  if(( buffer = ak_hash_ptr( handle, data, sizeof(data)-1, NULL )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong hash code calculation" );
    return ak_libakrypt_destroy();
  }

 /* вывод информации о результате вычисления */
  printf("obtained code size: %d bytes\n", (int) ak_buffer_get_size( buffer ));
  printf("hash: %s\n", str = ak_buffer_to_hexstr( buffer ));
  free(str);
  buffer = ak_buffer_delete( buffer );

 return ak_libakrypt_destroy(); /* останавливаем библиотеку и выходим */
}
