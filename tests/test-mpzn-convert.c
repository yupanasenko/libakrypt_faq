 #include <ak_mpzn.h>

/* основная тестирующая программа */
 int main( void )
{
  mpz_t xm, ym;
  ak_mpzn256 x, y;
  size_t i = 0, j = 0, len, count = 100000; /* количество тестов */
  struct random generator;
  char sx[160], sy[160];
  size_t cntstr = 0, cntmpz = 0, cntrev = 0;
  int exitcode = EXIT_SUCCESS;

  mpz_init( xm );
  mpz_init( ym );
  ak_libakrypt_create( ak_function_log_stderr );
  ak_random_context_create_lcg( &generator );

 /* путь преобразования и сравнения (функции сравнения считаются корректными):

    random -> mpzn (x) -> mpz (xm) -> mpzn (y) -> str (sy) -> mpzn (ym)
               |
               -> str (sx)

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
  if( cntstr != count ) exitcode = EXIT_FAILURE;
  if( cntmpz != count ) exitcode = EXIT_FAILURE;


  /*
    random -> str (sx) -> mpzn (x) -> str (sy)

    сравнение sx == sy
  */

  char digits[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                      '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

  cntstr = 0; cntmpz = 0; cntrev = 0;
  for( len = 1; len <= 64; len++ ) {
   /* тестируем строки всех длин от 1 до 64 символов (64 = 2*32 байта = 2* 256 бит) */

   for( i = 0; i < count; i++ ) {
      /* генерим случайную строку */
       memset( sx, 0, 160 );
       for( j = 0; j < len; j++ ) {
         ak_uint8 byte;
         generator.random( &generator, &byte, 1 );
         sx[j] = digits[byte&0xF];
       }
       if( ak_mpzn_set_hexstr( x, ak_mpzn256_size, sx ) != ak_error_ok ) cntstr++;
       if( ak_mpzn_to_hexstr_static( x, ak_mpzn256_size, sy, 160 ) != ak_error_ok ) cntrev++;
       if( !strncmp( sx, sy+64-len, 160 )) cntmpz++;
    }

    printf(" len: %2lu [correct: %lu, errors: %lu, %lu]\n", len, cntmpz, cntstr, cntrev );
    if( cntstr > 0 )  exitcode = EXIT_FAILURE;
    if( cntrev > 0 )  exitcode = EXIT_FAILURE;
    cntmpz = cntstr = cntrev = 0;
  }

  ak_random_context_destroy( &generator );
  ak_libakrypt_destroy();

 return exitcode;
}
