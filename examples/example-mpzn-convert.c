 #include <ak_mpzn.h>

/* основная тестирующая программа */
 int main( void )
{
  mpz_t xm, ym;
  ak_mpzn256 x, y;
  size_t i = 0, count = 100000; /* количество тестов */
  struct random generator;
  char sx[160], sy[160];
  size_t cntstr = 0, cntmpz = 0;

  mpz_init( xm );
  mpz_init( ym );
  ak_libakrypt_create( ak_function_log_stderr );
  ak_random_create_lcg( &generator );

 /* путь преобразования и сравнения (функции сравнения считаются корректными):

    random -> mpzn -> mpz -> mpzn (xm) -> str (sx)
               |
               -> str (sy) -> mpzn (ym)

    1) sx == sy (сравнение строк)
    2) xm == ym (сравнение mpz)
 */

  for( i = 0; i < count; i++ ) {
    /* генерация случайного числа */
     ak_mpzn_set_random( x, ak_mpzn256_size, &generator );
    /* преобразование в mpz_t */
     ak_mpzn_to_mpz( x, ak_mpzn256_size, xm );
    /* обратное преобразование */
     ak_mpz_to_mpzn( xm, y, ak_mpzn256_size );
     ak_ptr_to_hexstr_static( x, ak_mpzn256_size*sizeof( ak_uint64 ), sx, 160, ak_true );
     ak_ptr_to_hexstr_static( y, ak_mpzn256_size*sizeof( ak_uint64 ), sy, 160, ak_true );
    /* проверка совпадения строк, содержащих запись числа до преобразования и после */
     if( !strcmp( sx, sy )) cntstr++;

    /* преобразование строки в число mpz_t */
     mpz_set_str( ym, sy, 16 );
    /* сравнение двух чисел типа mpz_t */
     if( !mpz_cmp( xm, ym )) cntmpz++;
  }
  mpz_clear( ym );
  mpz_clear( xm );
  printf(" string comparison: %lu equals from %lu\n", cntstr, count );
  printf(" mpz_t comparison:  %lu equals from %lu\n", cntmpz, count );

  ak_random_destroy( &generator );
  ak_libakrypt_destroy();

 return 0;
}
