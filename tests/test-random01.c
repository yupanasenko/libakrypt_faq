/* Тестовый пример для оценки скорости реализации некоторых
   генераторов псевдо-случайных чисел.
   Пример использует неэкспортируемые функции.

   test-random01.c
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
 ak_uint8 seed[4] = { 0x13, 0xAE, 0x4F, 0x0E }; /* константа */
 int i = 0, retval = ak_true;
 ak_uint8 buffer[1024], string[2050];

 /* создаем генератор */
  create( &generator );
  printf( "%s: ", generator.oid->name ); fflush( stdout );

 /* инициализируем константным значением */
  if( generator.randomize_ptr != NULL )
    ak_random_context_randomize( &generator, &seed, sizeof( seed ));

 /* теперь вырабатываем необходимый тестовый объем данных */
  time = clock();
  for( i = 0; i < 1024*4; i++ ) ak_random_context_random( &generator, buffer, 1024 );
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
   if( test_function( ak_random_context_create_lcg,
      "47B7EF2B729133A3E9853E0F4FFE040154A7622B7827E71BC6E48DFF98C27F61" ) != ak_true )
     error = EXIT_FAILURE;

#ifdef _WIN32
 if( test_function( ak_random_context_create_winrtl, NULL ) != ak_true ) error = EXIT_FAILURE;
#endif
#if defined(__unix__) || defined(__APPLE__)
 if( test_function( ak_random_context_create_urandom, NULL ) != ak_true ) error = EXIT_FAILURE;
#endif

#ifdef LIBAKRYPT_CRYPTO_FUNCTIONS
 if( test_function( ak_random_context_create_hashrnd,
      "1C48E724F9A72C5889D5B98F2EFD54FB7272CA77A056FE1D015A6D7A2EC90CB3" ) != ak_true )
     error = EXIT_FAILURE;
#endif

 ak_libakrypt_destroy();
 return error;
}
