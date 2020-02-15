/* Пример иллюстрирует множество внутренних состояний секретного ключа электронной подписи.
   Внимание! Используются неэкспортируемые функции.

   test-sign01.c
*/
 #include <time.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <ak_oid.h>
 #include <ak_sign.h>
 #include <ak_parameters.h>

 int main( void )
{
  ak_oid oid = NULL;
  struct signkey key;
  ak_uint8 testkey[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x28 };

 /* инициализируем библиотеку */
  ak_log_set_level( ak_log_maximum );
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* ищем кривую для экспериментов */
  if(( oid = ak_oid_context_find_by_ni( "cspb" )) == NULL ) return ak_libakrypt_destroy();
 /* создаем ключ */
  ak_signkey_context_create_streebog256( &key, (ak_wcurve)oid->data );
 /* устанавливаем значение ключа */
  ak_signkey_context_set_key( &key, testkey, 32 );
 /* подстраиваем ключ и устанавливаем ресурс */
  ak_skey_context_set_resource( &key.key, key_using_resource,
               "digital_signature_count_resource", 0, time(NULL)+2592000 );
 /* выводим информацию о полях структуры */
  ak_skey_context_print_to_file( &key.key, stdout );
  ak_signkey_context_destroy( &key );

 /* создаем ключ для длинной подписи (512 бит) */
  memset( &key, 0, sizeof( struct signkey ));
  ak_signkey_context_create_oid( &key,
      ak_oid_context_find_by_ni( "sign512"),
      ak_oid_context_find_by_ni( "id-tc26-gost-3410-2012-512-paramSetA" ));

 /* устанавливаем случайное значение ключа */
  ak_signkey_context_set_key_random( &key,  &key.key.generator );
  ak_skey_context_print_to_file( &key.key, stdout );

 /* освобождаем память и выходим */
  ak_signkey_context_destroy( &key );
  ak_libakrypt_destroy();

 return EXIT_SUCCESS;
}
