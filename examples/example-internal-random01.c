/* Тестовый пример для оценки скорости реализации некоторых
   генераторов псевдослучайных чисел.

   example-internal-random01.c
*/

#include <time.h>
#include <stdio.h>
#include <ak_random.h>

 int test_function( const char *name, const char *result, ak_function_random create )
{ 
 clock_t time;
 struct random generator;
 ak_uint32 seed = 0x13AE4F0A;
 int i = 0, retval = ak_true;
 ak_uint8 buffer[1024], string[2050];

 /* создаем генератор */
  printf( "%s: ", name ); fflush( stdout );
  create( &generator );

 /* инициализируем константным значением */
  if( generator.randomize_ptr != NULL ) /* функция может быть не определена */
    generator.randomize_ptr( &generator, &seed, sizeof( seed ));

 /* теперь вырабатываем необходимый объем данных */
   time = clock();
   for( i = 0; i < 2*1024*1024; i++ ) generator.random( &generator, buffer, 1024 );
   time = clock() - time;

   ak_ptr_to_hexstr_static( buffer, 32, string, 2050, ak_false );
   printf("%s (%f sec)\n", string, (double)time / (double)CLOCKS_PER_SEC );

   if( generator.randomize_ptr != NULL ) { /* проверка только для тех, кому устанавливали
                                                                       начальное значение */
     if( memcmp( result, string, 32 ) != 0 ) retval = ak_false;
   }

  ak_random_context_destroy( &generator );
 return retval;
}


 int main( void )
{
 /* последовательно запускаем генераторы на тестирование */
 if( test_function( "xorshift",
                    "0B410050F2146C66EB11C3A0DFFA88B92978D0FD132E8837F8B04643F7ACD4CB",
                    ak_random_context_create_xorshift64 ) != ak_true ) return EXIT_FAILURE;

 if( test_function( "lcg",
                    "A6F1DB7846B992AF9B513A8EF42E898C6035D5696A77D1F7DCF24DD57F55F82D",
                    ak_random_context_create_lcg ) != ak_true ) return EXIT_FAILURE;

 if( test_function( "/dev/urandom",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    ak_random_context_create_urandom ) != ak_true ) return EXIT_FAILURE;

 return EXIT_SUCCESS;
}
