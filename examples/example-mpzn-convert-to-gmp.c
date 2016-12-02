 #include <libakrypt.h>
 #include <ak_mpzn.h>
 #include <gmp.h>

/* преобразование "туда и обратно" */
 void ak_mpzn_to_mpz( const ak_uint64 *x, const size_t size, mpz_t xm )
{
 mpz_import( xm, size, -1, sizeof( ak_uint64 ), 0, 0, x );
}

 void ak_mpz_to_mpzn( const mpz_t xm, ak_uint64 *x, const size_t size )
{
 memcpy( x, xm->_mp_d, size*sizeof( ak_uint64 ));
}

/* основная тестирующая программа */
 int main( void )
{
  mpz_t xm, ym;
  ak_mpzn256 x, y;
  size_t i = 0, count = 100000; /* количество тестов */
  ak_random generator = ak_random_new_lcg();
  char *sx, *sy;
  size_t cntstr = 0, cntmpz = 0;

  mpz_init( xm );
  mpz_init( ym );
  for( i = 0; i < count; i++ ) {
    /* генерация случайного числа */
     ak_mpzn_set_random( x, ak_mpzn256_size, generator );
    /* преобразование в mpz_t */
     ak_mpzn_to_mpz( x, ak_mpzn256_size, xm );
    /* обратное преобразование */
     ak_mpz_to_mpzn( xm, y, ak_mpzn256_size );
     sx = ak_ptr_to_hexstr( x, ak_mpzn256_size*sizeof( ak_uint64 ), ak_true );
     sy = ak_ptr_to_hexstr( y, ak_mpzn256_size*sizeof( ak_uint64 ), ak_true );
    /* проверка совпадения строк, содержащих запись числа до преобразования и после */
     if( !strcmp( sx, sy )) cntstr++;
    /* преобразование строки в число mpz_t */
     mpz_set_str( ym, sy, 16 );
    /* сравнение двух чисел типа mpz_t */
     if( !mpz_cmp( xm, ym )) cntmpz++;
     free(sx); free( sy );
  }
  mpz_clear( ym );
  mpz_clear( xm );
  printf(" string comparison: %lu equals from %lu\n", cntstr, count );
  printf(" mpz_t comparison:  %lu equals from %lu\n", cntmpz, count );
  generator = ak_random_delete( generator );

 return 0;
}
