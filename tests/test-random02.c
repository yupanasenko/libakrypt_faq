/* Тестовый пример, иллюстрирующий создание серии генераторов hashrnd
   и проверку последовательной выработки псевдослучайных значений.
   Пример использует неэкспортируемые функции.

   test-random02.c
*/

 #include <time.h>
 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
 #include <ak_hash.h>
 #include <ak_random.h>

 int main( void )
{
  size_t off = 0;
  int result = EXIT_FAILURE;
  const char *str = NULL;
  struct hash hctx;
  struct random rnd;
  ak_uint8 cnt[128], buffer[526], out[32], out2[32];

  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* 1. создаем константное значение */
  memset( cnt, ak_random_value()&0xFF, sizeof( cnt )); /* константа */
  if( ak_random_context_create_hashrnd( &rnd ) != ak_error_ok ) goto bad; /* создаем контекст генератора */
  ak_random_context_randomize( &rnd, cnt, sizeof( cnt )); /* инициализируем генератор константой */
  ak_random_context_random( &rnd, buffer, sizeof( buffer )); /* вырабатываем псевдослучайное значение */

  ak_hash_context_create_streebog256( &hctx ); /* вычисляем контрольную сумму */
  ak_hash_context_ptr( &hctx, buffer, sizeof( buffer ), out, sizeof( out ));

  if(( str = ak_ptr_to_hexstr( buffer, sizeof( buffer ), ak_false )) != NULL )
    printf("random data: %s ", str );
   else {
    printf("random data: %s ", str = (const char *)ak_ptr_to_hexstr_alloc( buffer, sizeof( buffer ), ak_false ));
    free( (char *)str );
   }
  printf("(hash: %s)\n\n", ak_ptr_to_hexstr( out, sizeof( out ), ak_false ));
  ak_random_context_destroy( &rnd );
  memset( buffer, 0, sizeof( buffer ));

 /* теперь тот же массив данных, но короткими фрагментами */
  ak_random_context_create_hashrnd( &rnd ); /* создаем контекст генератора */
  ak_random_context_randomize( &rnd, cnt, sizeof( cnt )); /* инициализируем генератор константой */

  printf("chunks: "); /* производим выработку гаммы случайными фрагментами */
  while( off < sizeof( buffer )) {
    size_t len = ak_min( ak_random_value()%32, sizeof( buffer ) - off );
    if( len > 0 ) {
      printf("%d ", (ak_int32)len );
      ak_random_context_random( &rnd, buffer+off, ( ssize_t )len );
      off += len;
    }
  }

  if(( str = ak_ptr_to_hexstr( buffer, sizeof( buffer ), ak_false )) != NULL )
    printf("random data: %s ", str );
   else {
    printf("random data: %s ", str = (const char *)ak_ptr_to_hexstr_alloc( buffer, sizeof( buffer ), ak_false ));
    free( (char *)str );
   }
  ak_hash_context_ptr( &hctx, buffer, sizeof( buffer ), out2, sizeof( out2 ));
  printf("(hash: %s)\n\ntest is ", ak_ptr_to_hexstr( out2, sizeof( out2 ), ak_false ));
  ak_random_context_destroy( &rnd );

 /* проверяем, что данные одинаковы */
  if( ak_ptr_is_equal( out, out2, sizeof( out ))) {
    result = EXIT_SUCCESS;
    printf("Ok\n");
  } else printf("Wrong\n");

 bad:
  ak_libakrypt_destroy();
  return result;
}
