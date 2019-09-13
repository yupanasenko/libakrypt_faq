/* Пример иллюстрирует эквивалентность реализации функции ak_hmac_context_file()
   и последовательности ak_hmac_context_clean()
                                       _update()
                                       _finalize()
   Внимание! Используются неэкспортируемые функции.

   test-hmac02.c
*/
 #include <time.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <ak_hmac.h>
 #include <ak_tools.h>

 void print_skey_info( ak_skey key );

 int main( int argc, char *argv[] )
{
  size_t i;
  ssize_t len;
  struct hmac hctx;
  struct file fp;
  ak_uint8 out[64], out2[64], buffer[4096];
  char *filename = NULL;
  int exitcode = EXIT_FAILURE;

 /* выбираем имя файла */
  if( argc > 1 ) filename = argv[1];
   else filename = argv[0];
  memset( out, 0, sizeof( out ));
  memset( out2, 0, sizeof( out2 ));

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* создаем и инициализируем контекст алгоритма hmac случайным ключом */
  ak_hmac_context_create_streebog256( &hctx );
  ak_hmac_context_set_key_random( &hctx, &hctx.key.generator );
  print_skey_info( &hctx.key );

 /* вычисляем имитовставку от заданного файла */
  ak_hmac_context_file( &hctx, filename, out, sizeof( out ));

 /* выводим результаты */
  printf("%s: ", hctx.key.oid->name );
  for( i = 0; i < ak_hmac_context_get_tag_size( &hctx); i++ ) printf("%02x", out[i] );
  printf(" (%s)\n", filename );

 /* теперь обрабатываем данные, считываемые из файла по-блочно */
  ak_hmac_context_clean( &hctx );
  ak_file_open_to_read( &fp, filename );
  while(( len = ak_file_read( &fp, buffer, sizeof( buffer ))) != 0 ) {
    ak_hmac_context_update( &hctx, buffer, (size_t)len );
  }
  ak_hmac_context_finalize( &hctx, NULL, 0, out2, sizeof( out2 ));
  ak_file_close( &fp );

  printf("%s: ", hctx.key.oid->name );
  for( i = 0; i < ak_hmac_context_get_tag_size( &hctx ); i++ ) printf("%02x", out2[i] );
  printf(" (block by block)\n" );

  if( ak_ptr_is_equal( out, out2, ak_hmac_context_get_tag_size( &hctx )))
    exitcode = EXIT_SUCCESS;

 /* завершаем работу */
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
