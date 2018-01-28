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
 /* значение, которое должно быть вычислено */
  ak_uint8 lazy[32] = {
   0x3E, 0x7D, 0xEA, 0x7F, 0x23, 0x84, 0xB6, 0xC5, 0xA3, 0xD0, 0xE2, 0x4A, 0xAA, 0x29, 0xC0, 0x5E,
   0x89, 0xDD, 0xD7, 0x62, 0x14, 0x50, 0x30, 0xEC, 0x22, 0xC7, 0x1A, 0x6D, 0xB8, 0xB2, 0xC1, 0xF4 };

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
  printf("hash: %s (calculated)\n", str = ak_buffer_to_hexstr( buffer ));
  free(str);
  buffer = ak_buffer_delete( buffer );

 /* вывод заранее подсчитанной константы */
  printf("hash: %s (expected)\n", str = ak_ptr_to_hexstr( lazy, sizeof( lazy ), ak_false ));
  free(str);

 return ak_libakrypt_destroy(); /* останавливаем библиотеку и выходим */
}
