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
  char *str = NULL;
  mpz_t xm, pm;
  ak_mpzn256 x, p;
  size_t i = 0, count = 100000, resc = 0; /* количество тестов */
  ak_random generator = ak_random_new_lcg();
  int res = ak_mpzn_set_hexstr( p, ak_mpzn256_size, // "200000000000000000000000000000000" );
                                    "80006E0260AA354F8B3BDE32192F7D9B67BE2308AA1BD6AEFFD300CF9BD87547");
  printf("p = %s (covert code: %d)\n", str = ak_mpzn_to_hexstr( p, ak_mpzn256_size ), res );
  free( str );

  mpz_init( xm );
  mpz_init( pm );
  ak_mpzn_to_mpz( p, ak_mpzn256_size, pm );
  for( i = 1; i <= count; i++ ) {
     ak_mpzn_set_random_modulo( x, p, ak_mpzn256_size, generator );
     if( i%1000 == 0 ) {
        printf("idx: %6lu, x = %s\n", i, str = ak_mpzn_to_hexstr( x, ak_mpzn256_size ));
        free(str);
     }
     ak_mpzn_to_mpz( x, ak_mpzn256_size, xm );
     if( mpz_cmp( pm, xm ) == 1 ) { ++resc; }
  }
  mpz_clear(pm);
  mpz_clear(xm);
  generator = ak_random_delete( generator );

  printf("successfully tested %ld from %ld\n", resc, count );

 return 0;
}
