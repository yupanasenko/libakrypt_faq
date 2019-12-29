/* Пример иллюстрирует процедуры преобразования секретного ключа
   в der-последовательность
   Внимание! Используются неэкспортируемые функции.

   test-skey02.c
*/
 #include <time.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <ak_skey.h>
 #include <ak_asn1.h>

 int main( void )
{
  struct skey key;
  struct asn1 root;
  ak_uint8 testkey[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x28 };

 /* инициализируем библиотеку */
  ak_log_set_level( ak_log_maximum );
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* создаем ключ и инициализуем его неким значением */
  ak_skey_context_create( &key, 32 );
  ak_skey_context_set_key( &key, testkey, 32 );
 /* устанавливаем ресурс ключа */
  ak_skey_context_set_resource( &key, key_using_resource, "hmac_key_count_resource", 0, time(NULL)+2592000 );
  ak_skey_context_print_to_file( &key, stdout );

  ak_asn1 asn1;

  ak_asn1_context_create( asn1 = malloc( sizeof( struct asn1 )));
  ak_asn1_context_add_uint32( asn1, key.resource.value.type );
  ak_asn1_context_add_uint32( asn1, key.resource.value.counter );
  ak_asn1_context_add_time_validity( asn1, key.resource.time.not_before, key.resource.time.not_after );

  ak_asn1_context_create( &root );
  ak_asn1_context_add_oid( &root, "1.0.0.0.1.1.1.0.0.0.1" );
  ak_asn1_context_add_octet_string( &root, key.number, sizeof( key.number ));
  ak_asn1_context_add_asn1( &root, TSEQUENCE, asn1 );

  ak_asn1_context_print( &root, stdout );
  ak_asn1_context_destroy( &root );


  ak_skey_context_destroy( &key );
  ak_libakrypt_destroy();
 return EXIT_SUCCESS;
}
