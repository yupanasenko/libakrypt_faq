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

 int test_function( const char *name, const char *result, ak_function_random create )
{ 
 clock_t time;
 struct random generator;
 ak_uint32 seed = 0x13AE4F0A;
 int i = 0, excode = ak_error_ok, retval = ak_true;
 ak_uint8 buffer[1024], string[2050];

 /* создаем генератор */
  printf( "%s: ", name ); fflush( stdout );
  create( &generator );

 /* инициализируем константным значением */
  excode = ak_random_context_randomize( &generator, &seed, sizeof( seed ));

 /* теперь вырабатываем необходимый объем данных - 2ГБ */
   time = clock();
   for( i = 0; i < 2*1024*1024; i++ ) ak_random_context_random( &generator, buffer, 1024 );
   time = clock() - time;

   ak_ptr_to_hexstr_static( buffer, 32, string, 2050, ak_false );
   printf("%s (%f sec)\n", string, (double)time / (double)CLOCKS_PER_SEC );

   if( excode == ak_error_ok ) /* проверка только для тех, кому устанавливали
                                                                    начальное значение */
     if( memcmp( result, string, 32 ) != 0 ) retval = ak_false;

  ak_random_context_destroy( &generator );
 return retval;
}

 int main( void )
{
 printf("random generators speed test for libakrypt, version %s\n", ak_libakrypt_version( ));
 if( !ak_libakrypt_create( NULL )) return ak_libakrypt_destroy();

 /* последовательно запускаем генераторы на тестирование */
 if( test_function( "xorshift",
                    "5CD6E4D62B79C1C97921693A1AC587D608D3B6EA03A72E2AE4B41927E6B82221",
                    ak_random_context_create_xorshift32 ) != ak_true ) return EXIT_FAILURE;

 if( test_function( "lcg",
                    "A6F1DB7846B992AF9B513A8EF42E898C6035D5696A77D1F7DCF24DD57F55F82D",
                    ak_random_context_create_lcg ) != ak_true ) return EXIT_FAILURE;

#ifdef WIN32
 if( test_function( "winrtl",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    ak_random_context_create_winrtl ) != ak_true ) return EXIT_FAILURE;
#else
 if( test_function( "/dev/urandom",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    ak_random_context_create_urandom ) != ak_true ) return EXIT_FAILURE;
#endif

// #include <ak_mpzn.h>

// char s[160];
// ak_mpzn512 x, y;

// ak_mpzn_set_hexstr( x, ak_mpzn256_size, "11234567890abcdfef0123456789accfead" );
// ak_mpzn_to_hexstr_static( x, ak_mpzn256_size, s, sizeof(s));
// printf("x: %s [", s );
// for( int i = 0; i < ak_mpzn256_size; i++ ) printf("%llu ", x[i] );
// printf("]\n");

// ak_mpzn_set_hexstr( y, ak_mpzn256_size, "20781accdefa223675645cceffd011" );
// ak_mpzn_to_hexstr_static( y, ak_mpzn256_size, s, sizeof(s));
// printf("y: %s [", s );
// for( int i = 0; i < ak_mpzn256_size; i++ ) printf("%llu ", y[i] );
// printf("]\n");

// ak_mpzn_mul( x, x, y, ak_mpzn256_size );
// ak_mpzn_to_hexstr_static( x, 5, s, sizeof(s));
// printf("z: %s [", s );
// for( int i = 0; i < 5; i++ ) printf("%0llu ", x[i] );
// printf("]\n");

// /* далее, удалить */
//  #include <ak_curves.h>

//  union {
//   ak_uint64 x;
//   ak_uint8 c[8];
//  } un;
//  ak_oid oid = ak_oid_context_find_by_engine( identifier );

//  while( oid != NULL ) {
//    int j, i = 0;
//    if( oid->mode == wcurve_params ) {
//      ak_wcurve wc = NULL;
//      if(( wc = ( ak_wcurve ) oid->data ) == NULL )  {
//        ak_error_message( ak_error_null_pointer, __func__,
//                                      "internal error with null pointer to wcurve paramset" );
//      }

//      printf("%s\n", oid->name );
//      printf(" { ");
//      for( i = 0; i < wc->size; i++ ) {
//         un.x = wc->a[i]; printf(" 0x");
//         for( j = 0; j < 8; j++ ) printf("%02x", un.c[j] );
//         printf(",");
//      }
//      printf(" },\n");
//      printf(" { ");
//      for( i = 0; i < wc->size; i++ ) {
//         un.x = wc->b[i]; printf(" 0x");
//         for( j = 0; j < 8; j++ ) printf("%02x", un.c[j] );
//         printf(",");
//      }
//      printf(" },\n");
//      printf(" { ");
//      for( i = 0; i < wc->size; i++ ) {
//         un.x = wc->p[i]; printf(" 0x");
//         for( j = 0; j < 8; j++ ) printf("%02x", un.c[j] );
//         printf(",");
//      }
//      printf(" },\n");
//      printf(" { ");
//      for( i = 0; i < wc->size; i++ ) {
//         un.x = wc->r2[i]; printf(" 0x");
//         for( j = 0; j < 8; j++ ) printf("%02x", un.c[j] );
//         printf(",");
//      }
//      printf(" },\n");
//      printf(" { ");
//      for( i = 0; i < wc->size; i++ ) {
//         un.x = wc->q[i]; printf(" 0x");
//         for( j = 0; j < 8; j++ ) printf("%02x", un.c[j] );
//         printf(",");
//      }
//      printf(" },\n");
//      printf(" { ");
//      for( i = 0; i < wc->size; i++ ) {
//         un.x = wc->r2q[i]; printf(" 0x");
//         for( j = 0; j < 8; j++ ) printf("%02x", un.c[j] );
//         printf(",");
//      }
//      printf(" },\n");

//      printf(" { ");
//      for( i = 0; i < wc->size; i++ ) {
//         un.x = wc->point.x[i]; printf(" 0x");
//         for( j = 0; j < 8; j++ ) printf("%02x", un.c[j] );
//         printf(",");
//      }
//      printf(" },\n");
//      printf(" { ");
//      for( i = 0; i < wc->size; i++ ) {
//         un.x = wc->point.y[i]; printf(" 0x");
//         for( j = 0; j < 8; j++ ) printf("%02x", un.c[j] );
//         printf(",");
//      }
//      printf(" },\n");
//      printf(" { ");
//      for( i = 0; i < wc->size; i++ ) {
//         un.x = wc->point.z[i]; printf(" 0x");
//         for( j = 0; j < 8; j++ ) printf("%02x", un.c[j] );
//         printf(",");
//      }
//      printf(" },\n");

//      un.x = wc->n; printf(" 0x");
//      for( j = 0; j < 8; j++ ) printf("%02x", un.c[j] );
//      printf("LL,\n");
//      un.x = wc->nq; printf(" 0x");
//      for( j = 0; j < 8; j++ ) printf("%02x", un.c[j] );
//      printf("LL,\n");
//    }

//    printf("\n");
//    oid = ak_oid_context_findnext_by_engine( oid, identifier );
//  }

 ak_libakrypt_destroy();
 return EXIT_SUCCESS;
}
