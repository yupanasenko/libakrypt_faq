/* Тестовый пример, иллюстрирующий создание серии генераторов,
   основанных на применении функций хеширования (hashrnd).
   Пример использует неэкспортируемые функции.

   test-internal-random02.c
*/

 #include <time.h>
 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
 #include <ak_oid.h>
 #include <ak_hash.h>
 #include <ak_random.h>

/* функция, тестирующая совпадение различных путей вызова генератора */
 int test( ak_oid oid )
{
  int i = 0;
  size_t len, offset;
  struct hash streebog;
  struct random generator;
  int exitcode = EXIT_SUCCESS;
  ak_uint8 cnt[128], buffer[526], out[32], out2[32], string[2050];

  if( oid == NULL ) return EXIT_FAILURE;
  printf("\nTest for %s hash function\n", oid->name );
  ak_hash_context_create_streebog256( &streebog ); /* хеш для контрольной суммы */

 /* 1. создаем константное значение */
  memset( cnt, rand()%256, sizeof( cnt )); /* константа */
  ak_random_context_create_hashrnd_oid( &generator, oid ); /* создаем контекст генератора */
  ak_random_context_randomize( &generator, cnt, sizeof( cnt )); /* инициализируем генератор константой */
  ak_random_context_random( &generator, buffer, sizeof( buffer )); /* вырабатываем псевдослучайное значение */

  ak_ptr_to_hexstr_static( buffer, sizeof( buffer ), string, sizeof( string ), ak_false );
  printf("data: %s\n\n", string );

  ak_hash_context_ptr( &streebog, buffer, sizeof( buffer ), out ); /* контрольная сумма от выработанных данных */
  ak_ptr_to_hexstr_static( out, sizeof( out ), string, sizeof( string ), ak_false );
  printf("hash: %s\n", string );

 /* 2. теперь генерация тех же данных фрагментами случайной длины (используем rand( )) */
 for( i = 0; i < 10; i++ ) {
    offset = 0;
    len = sizeof( buffer );
    ak_random_context_randomize( &generator, cnt, sizeof( cnt )); /* инициализируем генератор константой */

    while( len > 0 ) { /* реализации последователных вызовов со случайной длиной запрашиваемых данных */
      size_t val = 2 + rand()%13;
      if( val > len ) val = len;
      ak_random_context_random( &generator, buffer+offset, val );
      offset += val;
      len -= val;
    }
    ak_hash_context_ptr( &streebog, buffer, sizeof( buffer ), out2 ); /* контрольная сумма от выработанных данных */
    ak_ptr_to_hexstr_static( out2, sizeof( out2 ), string, sizeof( string ), ak_false );
    printf("hash: %s", string );
    if( ak_ptr_is_equal( out, out2, sizeof( out ))) printf(" Ok\n");
     else {
            printf("Wrong\n");
            exitcode = EXIT_FAILURE;
          }
  }

 /* Освобождаем память */
  ak_random_context_destroy( &generator );
  ak_hash_context_destroy( &streebog );

 return exitcode;
}


 int main( void )
{
  int error = EXIT_SUCCESS;
  if( !ak_libakrypt_create( NULL )) return ak_libakrypt_destroy();

  if(( error = test( ak_oid_context_find_by_name( "streebog256" ))) != EXIT_SUCCESS ) goto exitlab;
  if(( error = test( ak_oid_context_find_by_name( "streebog512" ))) != EXIT_SUCCESS ) goto exitlab;

  exitlab: ak_libakrypt_destroy();
 return error;
}
