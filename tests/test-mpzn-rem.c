 #include <ak_curves.h>
 #include <ak_mpzn.h>
 #include <ak_oid.h>
 #include <ak_context_manager.h>
 #include <gmp.h>

/* ----------------------------------------------------------------------------------------------- */
 int mpzn_rem_test( ak_wcurve wc, size_t count )
{
  int rescount = 0;
  size_t j = 0, mycount = 0, mpzcount = 0;
  ak_mpznmax x, r, l;
  ak_uint64 *p = wc->p;
  mpz_t xp, rp, pp;
  struct random generator;

  mpz_init( xp );
  mpz_init( rp );
  mpz_init( pp );
  ak_random_create_lcg( &generator );

 /* первый тест - модуль p */
  ak_mpzn_to_mpz( p, wc->size, pp );
  printf(" - p: "); mpz_out_str( stdout, 16, pp ); printf("\n");

  for( j = 0; j < count; j++ ) {
     ak_mpzn_set_random( x, wc->size, &generator );
     ak_mpzn_rem( r, x, p, wc->size ); /* r <- x (mod p) */

     ak_mpzn_to_mpz( x, wc->size, xp );
     mpz_mod( rp, xp, pp ); /* rp <- xp (mod pp) */

     ak_mpzn_to_mpz( r, wc->size, xp ); if( !mpz_cmp( rp, xp )) mpzcount++;
     ak_mpz_to_mpzn( rp, l, wc->size ); if( !ak_mpzn_cmp( r, l, wc->size )) mycount++;
  }
  printf(" %lu (%lu) tests passed successfully from %lu \n", mpzcount, mycount, count );
  if(( mpzcount == count ) && (  mycount == count )) rescount++;

 /* второй тест - модуль q */

  ak_mpzn_to_mpz( p = wc->q, wc->size, pp );
  printf(" - q: "); mpz_out_str( stdout, 16, pp ); printf("\n");

  mpzcount = mycount = 0;
  for( j = 0; j < count; j++ ) {
     ak_mpzn_set_random( x, wc->size, &generator );
     ak_mpzn_rem( r, x, p, wc->size ); /* r <- x (mod p) */

     ak_mpzn_to_mpz( x, wc->size, xp );
     mpz_mod( rp, xp, pp ); /* rp <- xp (mod pp) */

     ak_mpzn_to_mpz( r, wc->size, xp ); if( !mpz_cmp( rp, xp )) mpzcount++;
     ak_mpz_to_mpzn( rp, l, wc->size ); if( !ak_mpzn_cmp( r, l, wc->size )) mycount++;
  }
  printf(" %lu (%lu) tests passed successfully from %lu \n", mpzcount, mycount, count );
  if(( mpzcount == count ) && (  mycount == count )) rescount++;

  ak_random_destroy( &generator );
  mpz_clear( xp );
  mpz_clear( rp );
  mpz_clear( pp );

 return rescount;
}

/* ----------------------------------------------------------------------------------------------- */
/* основная тестирующая программа */
 int main( void )
{
  ak_oid oid = NULL;
  int totalmany = 0, howmany = 0;
  ak_libakrypt_create( ak_function_log_stderr );

 /* организуем цикл по перебору всех известных простых чисел */
  oid = ak_oid_find_by_engine( identifier );

  while( oid != NULL ) {
    if( oid->mode == wcurve_params ) {
     /* достаем простое число */
      totalmany += 2;
      howmany += mpzn_rem_test( (ak_wcurve)(oid->data), 1000000 );
    }
    oid = ak_oid_findnext_by_engine( oid, identifier );
  }

  printf("\n total remainder tests: %d (passed: %d)\n", totalmany, howmany );
 return ak_libakrypt_destroy();
}
