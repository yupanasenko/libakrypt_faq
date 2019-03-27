/* Тестовый пример для оценки скорости реализации некоторых
   генераторов псевдо-случайных чисел.
   Пример использует неэкспортируемые функции.

   test-internal-random01.c
*/

 #include <time.h>
 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
 #include <ak_random.h>

/* основная тестирующая функция */
 int test_function( ak_function_random create, const char *result )
{ 
 clock_t time;
 struct random generator;
 ak_uint32 seed = 0x13AE4F0E; /* константа */
 int i = 0, retval = ak_true;
 ak_uint8 buffer[1024], string[2050];

 /* создаем генератор */
  create( &generator );
  printf( "%s: ", generator.oid->name ); fflush( stdout );

 /* инициализируем константным значением */
  if( generator.randomize_ptr != NULL )
    ak_random_context_randomize( &generator, &seed, sizeof( seed ));

 /* теперь вырабатываем необходимый объем данных - 256МБ */
  time = clock();
  for( i = 0; i < 1024*128; i++ ) ak_random_context_random( &generator, buffer, 1024 );
  time = clock() - time;

  ak_ptr_to_hexstr_static( buffer, 32, string, 2050, ak_false );
  printf("%s (%f sec) ", string, (double)time / (double)CLOCKS_PER_SEC );

 /* проверка только для тех, кому устанавливали начальное значение */
  if( result ) {
    if( memcmp( result, string, 32 ) != 0 ) { printf("Wrong\n"); retval = ak_false; }
     else { printf("Ok\n"); retval = ak_true; }
  } else { printf("\n"); retval = ak_true; }

  ak_random_context_destroy( &generator );
 return retval;
}

 int main( void )
{
 int error = EXIT_SUCCESS;

 printf("random generators speed test for libakrypt, version %s\n", ak_libakrypt_version( ));
 if( !ak_libakrypt_create( NULL )) return ak_libakrypt_destroy();

 /* последовательно запускаем генераторы на тестирование */
 if( test_function( ak_random_context_create_xorshift32,
      "2B7D8650FA05497B21683B25FEEBD24FA877094796297456958696BBD775C603" ) != ak_true )
   error =  EXIT_FAILURE;

 if( test_function( ak_random_context_create_lcg,
      "60ACB367D8624B6D5C3984D78E19A9CC52D9244386003BBFCA80D315387C2F23" ) != ak_true )
   error = EXIT_FAILURE;

#ifdef WIN32
 if( test_function( ak_random_context_create_winrtl, NULL ) != ak_true ) error = EXIT_FAILURE;
#endif
#if defined(__unix__) || defined(__APPLE__)
 if( test_function( ak_random_context_create_urandom, NULL ) != ak_true ) error = EXIT_FAILURE;
#endif

#ifdef LIBAKRYPT_CRYPTO_FUNCTIONS
 if( test_function( ak_random_context_create_hashrnd_streebog512,
      "F59B4AC1EFEEDD34E0BC8875BE96C1EE89901F9153F949DDA6BC666512F41375" ) != ak_true )
   error = EXIT_FAILURE;
#endif

 ak_libakrypt_destroy();
 return error;
}
