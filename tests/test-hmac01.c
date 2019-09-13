/* Пример иллюстрирует работу с контекстом hmac.
   Иллюстрируется жквивалентность вызовов функции ak_hmac_context_ptr()
   и последовательности ak_hmac_context_clean()
                                       _update()
                                       _finalize()
   Внимание! Используются неэкспортируемые функции.

   test-hmac01.c
*/
 #include <time.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <ak_hmac.h>

/* функия вывода информации о секретном ключе */
 void print_skey_info( ak_skey );

 int main( void )
{
  size_t i, j;
  struct hmac hctx;
  struct random generator;
  int exitcode = EXIT_FAILURE;
  ak_uint8 testkey[293], out1[128], out2[128];

 /* инициализируем библиотеку */
  ak_log_set_level( ak_log_maximum );
  if( !ak_libakrypt_create( NULL )) return ak_libakrypt_destroy();

 /* вырабатываем случайные данные */
  ak_random_context_create_lcg( &generator );
  ak_random_context_random( &generator, testkey, sizeof( testkey ));
  ak_random_context_destroy( &generator );

 /* создаем контекст */
  ak_hmac_context_create_streebog512( &hctx );
 /* присваиваем ключ */
  ak_hmac_context_set_key( &hctx, testkey, sizeof( testkey ));
  print_skey_info( &hctx.key );

 /* теперь запускаем цикл тестирования */
  for( j = 3; j < sizeof( testkey ); j++ ) {
   /* вычисление результата за один вызов */
    ak_hmac_context_ptr( &hctx, testkey, j, out1, sizeof( out1 ));

   /* последовательное вычисление результата */
    ak_hmac_context_clean( &hctx );
    for( i = 0; i < j; i++ ) ak_hmac_context_update( &hctx, testkey+i, 1 );
    ak_hmac_context_finalize( &hctx, NULL, 0, out2, sizeof( out2 ));

   /* сравнение результатов */
    if( !ak_ptr_is_equal( out1, out2, ak_hmac_context_get_tag_size( &hctx ))) {
      printf(" Wrong (test %u)\n", (unsigned int)j );
      goto label_exit;
    }
    if( j%64 == 3 ) printf("\n");
    printf("."); fflush( stdout );
  }
  printf(" Ok (%u tests)\n", (unsigned int)(sizeof( testkey ) - 3 ));
  exitcode = EXIT_SUCCESS;

 /* освобождаем память и выходим */
  label_exit:
   ak_hmac_context_destroy( &hctx );
   ak_libakrypt_destroy();

 return exitcode;
}

 void print_skey_info( ak_skey key )
{
  size_t i = 0;
  char *bc = "block counter", *rc = "key usage counter";

 /* информация о ключе */
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
