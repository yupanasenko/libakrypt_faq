/* Пример иллюстрирует множество внутренних состояний секретного ключа.
   Внимание! Используются неэкспортируемые функции.

   test-skey01.c
*/
 #include <time.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <ak_skey.h>

 int main( void )
{
  struct skey key;
  ak_uint8 testkey[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x28 };

 /* инициализируем библиотеку */
  ak_log_set_level( ak_log_maximum );
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* создаем ключ */
  ak_skey_context_create( &key, 32 );
 /* устанавливаем значение ключа */
  ak_skey_context_set_key( &key, testkey, 32 );
 /* устанавливаем ресурс ключа */
  ak_skey_context_set_resource( &key, key_using_resource, "hmac_key_count_resource", 0, time(NULL)+2592000 );
 /* выводим информацию о полях структуры */
  ak_skey_context_print_to_file( &key, stdout );

 /* ус танавливаем случайное значение */
  ak_skey_context_set_key_random( &key,  &key.generator );
  ak_skey_context_print_to_file( &key, stdout );

 /* освобождаем память и выходим */
  ak_skey_context_destroy( &key );
  ak_libakrypt_destroy();

 return EXIT_SUCCESS;
}
