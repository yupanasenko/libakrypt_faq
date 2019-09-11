/* Пример иллюстрирует множество внутренних состояний секретного ключа.
   Внимание! Используются неэкспортируемые функции.

   test-skey01.c
*/
 #include <time.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <ak_skey.h>

 void print_skey_info( ak_skey key )
{
  size_t i = 0;
  char *bc = "block counter", *rc = "key usage counter";

 /* информация о ключе */
  printf("struct skey size: %u byte(s)\n", (unsigned int)sizeof( struct skey ));
  if( key->oid != NULL )
    printf("key info: %s (OID: %s, engine: %s, mode: %s)\n",  key->oid->name, key->oid->id,
    ak_libakrypt_get_engine_name( key->oid->engine ), ak_libakrypt_get_mode_name( key->oid->mode ));
   else printf("key info: unidentified\n");

  printf("unique number:\n\t");
  for( i = 0; i < sizeof( key->number ); i++ ) printf("%02X", key->number[i] );
  printf("\n");

  if( key->key != NULL ) {
    printf("fields:\n key:\t");
    for( i = 0; i < key->key_size; i++ ) printf("%02X", key->key[i] );
    printf("\n mask:\t");
    for( i = 0; i < key->key_size; i++ ) printf("%02X", key->key[i+key->key_size] );
  } else printf("secret key buffer is undefined\n");
  printf("\n icode:\t%08X", key->icode );
  if( key->check_icode( key ) == ak_true ) printf(" (Ok)\n");
   else printf(" (Wrong)\n");

  key->unmask( key ); /* снимаем маску */
  printf(" real:\t");
  for( i = 0; i < key->key_size; i++ ) printf("%02X", key->key[i] );
  printf("\n");
  key->set_mask( key );

  printf("resource:\n value:\t %u (%s)\n", (unsigned int)key->resource.value.counter,
                              key->resource.value.type == block_counter_resource ? bc : rc );
  printf(" not before: %s", ctime( &key->resource.time.not_before ));
  printf(" not after:  %s\n", ctime( &key->resource.time.not_after ));
}

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
 /* устанавливаем какой-нибудь OID (если такого нет, то маскируем ошибку) */
  if(( key.oid = ak_oid_context_find_by_name( "streebog512" )) == NULL ) ak_error_set_value( ak_error_ok );

 /* устанавливаем значение ключа */
  ak_skey_context_set_key( &key, testkey, 32 );
 /* устанавливаем ресурс ключа */
  ak_skey_context_set_resource( &key, key_using_resource, "hmac_key_count_resource", 0, time(NULL)+2592000 );
 /* выводим информацию о полях структуры */
  print_skey_info( &key );

 /* освобождаем память и выходим */
  ak_skey_context_destroy( &key );
  ak_libakrypt_destroy();

 return EXIT_SUCCESS;
}
