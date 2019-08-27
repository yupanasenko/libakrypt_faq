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
 #ifdef LIBAKRYPT_LITTLE_ENDIAN
   if( test_function( ak_random_context_create_xorshift32,
      "9D7130C59C3775ABBF9A50BD3C9AE26E2E990589FEC3287E752AB1ACCA1F06B6" ) != ak_true )
     error =  EXIT_FAILURE;
 #else
   if( test_function( ak_random_context_create_xorshift32,
      "A389BD971359E6CADF96904ABE650625CA9487D517AF56A252166BFF72514D2B" ) != ak_true )
     error =  EXIT_FAILURE;
 #endif

 #ifdef LIBAKRYPT_LITTLE_ENDIAN
   if( test_function( ak_random_context_create_lcg,
      "206C732798220B2D1CF944974ED9698C1299E40346C0FB7F8A4093D5F83CEFE3" ) != ak_true )
     error = EXIT_FAILURE;
 #else
   if( test_function( ak_random_context_create_lcg,
      "47B7EF2B729133A3E9853E0F4FFE040154A7622B7827E71BC6E48DFF98C27F61" ) != ak_true )
     error = EXIT_FAILURE;
 #endif

#ifdef _WIN32
 if( test_function( ak_random_context_create_winrtl, NULL ) != ak_true ) error = EXIT_FAILURE;
#endif
#if defined(__unix__) || defined(__APPLE__)
 if( test_function( ak_random_context_create_urandom, NULL ) != ak_true ) error = EXIT_FAILURE;
#endif

#ifdef LIBAKRYPT_CRYPTO_FUNCTIONS
 #ifdef LIBAKRYPT_LITTLE_ENDIAN
   if( test_function( ak_random_context_create_hashrnd_streebog512,
      "5ED8CE19B9F99E0E4837EAF2140A5E8FE3217BC9F1940CBEA34975FA8968E293" ) != ak_true )
     error = EXIT_FAILURE;
 #else
   if( test_function( ak_random_context_create_hashrnd_streebog512,
      "1005517034F6C6EB6DEDD3F7259BFB71AF06BC1F2AA2EFD554B090E2A4CB096D" ) != ak_true )
     error = EXIT_FAILURE;
 #endif
#endif

 ak_libakrypt_destroy();
 return error;
}
