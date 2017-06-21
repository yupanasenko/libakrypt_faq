 #include <libakrypt.h>

 int main( void )
{
 int i = 0;
 ak_uint64 seed = 0;
 unsigned char buff[128];
 ak_random generator = NULL; /* указатель на генератор псевдо-случайных чисел */

 /* инициализируем библиотеку */
 if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) return ak_libakrypt_destroy();

 /* создаем линейный конгруэнтный генератор со случайным внутренним состоянием */
 if((generator = ak_random_new_lcg()) != NULL )
   printf(" testing a linear congruence generator (lcg)\n");
  else return ak_libakrypt_destroy();

 /* вывод десяти случайных значений */
 printf(" -- random values:\n");
 for( i = 0; i < 10; i++ ) {
   ak_uint64 temp = ak_random_uint64( generator );
   printf(" %08X%08X\n", (ak_uint32)(temp >> 32 ), (ak_uint32)temp );
 }
 /* вводим новое инициализационное значение для генератора */
 printf(" input an initial seed:  "); fflush(stdout); scanf("%lu", &seed );
 ak_random_randomize_ptr( generator, &seed, sizeof( ak_uint64 ));

 /* вывод десяти 64-х битных значений */
 printf(" -- seeded values:\n");
 for( i = 0; i < 10; i++ ) {
   ak_uint64 temp = ak_random_uint64( generator );
   printf(" %08X%08X\n", (ak_uint32)(temp >> 32 ), (ak_uint32)temp );
 }

 /* тестируем загрузку данных в произвольную область память (массив) */
 printf(" -- buffer with %ld random bytes:\n", sizeof( buff ));
 ak_random_ptr( generator, buff, sizeof( buff ));
 for( i = 0; i < sizeof( buff ); i++ ) printf(" %02x", buff[i] );
 printf("\n");

 /* удаляем генератор и останавливаем библитеку */
 generator = ak_random_delete( generator );
 return ak_libakrypt_destroy();
}

