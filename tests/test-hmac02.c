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
  ak_skey_context_print_to_file( &hctx.key, stdout );

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
