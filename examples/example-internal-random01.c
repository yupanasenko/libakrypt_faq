/* Тестовый пример для оценки скорости реализации некоторых
   генераторов псевдослучайных чисел.

   example-internal-random01.c
*/

#include <time.h>
#include <stdio.h>
#include <ak_random.h>

 void test_function( char *name, ak_function_random create )
{
 int i = 0;
 clock_t time;
 struct random generator;
 ak_uint8 buffer[1024], string[2050];

 /* создаем и тестируем генератор */
  printf( "%s: ", name ); fflush( stdout );
  create( &generator );
   time = clock();
   for( i = 0; i < 2*1024*1024; i++ ) generator.random( &generator, buffer, 1024 );
   time = clock() - time;

   ak_ptr_to_hexstr_static( buffer, 32, string, 2050, ak_false );
   printf("%s (%f sec)\n", string, (double)time / (double)CLOCKS_PER_SEC );
  ak_random_context_destroy( &generator );
}


 int main( void )
{
 test_function( "xorshift", ak_random_context_create_xorshift64 );
 test_function( "lcg", ak_random_context_create_lcg );
 test_function( "/dev/urandom", ak_random_context_create_urandom );


 return EXIT_SUCCESS;
}
