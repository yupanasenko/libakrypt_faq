 #include <libakrypt.h>
 #include <ak_mpzn.h>
 #include <ak_curves.h>
 #include <ak_oid.h>
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
  size_t idx = 0, j, count = 0, mycount = 0, trycount = 10000000;
  char *str = NULL;
  ak_mpznmax x, r, l;
  mpz_t xp, rp, qp;
  ak_random generator = ak_random_new_lcg();
  clock_t tmr;

  ak_libakrypt_create( ak_function_log_stderr );
  mpz_init( xp );
  mpz_init( rp );
  mpz_init( qp );

 /* перебираем все кривые и хранящиеся в них простые модули */
  for( idx = 0; idx < ak_oids_get_count(); idx++ ) {
     ak_oid oid = ak_oids_get_oid( idx );
     if( ak_oid_get_mode( oid ) == wcurve_params ) {
       const ak_wcurve_paramset ecp = ( const ak_wcurve_paramset) oid->data;
       ak_wcurve ec = ak_wcurve_new( ecp );

      /* сначала тестируем модуль q, по которому будут производиться вычисления */
       printf(" curve OID: %s\nq = %s\n",
         ak_oid_get_id( oid ), str = ak_mpzn_to_hexstr( ec->q, ec->size ));
       free( str );
       ak_mpzn_to_mpz( ec->q, ec->size, qp );

       /* собственно тестирование операции взятия остатка */
       count = 0; mycount = 0;
       for( j = 0; j < trycount; j++ ) {
          ak_mpzn_set_random( x, ec->size, generator );
          ak_mpzn_to_mpz( x, ec->size, xp );

          ak_mpzn_rem( r, x, ec->q, ec->size );
          mpz_mod( rp, xp, qp );

          ak_mpzn_to_mpz( r, ec->size, xp ); if( !mpz_cmp( rp, xp )) count++;
          ak_mpz_to_mpzn( rp, l, ec->size ); if( !ak_mpzn_cmp( r, l, ec->size )) mycount++;
       }
       printf(" %lu (%lu) tests passed successfully from %lu --- ", count, mycount, trycount );
       if( (count == trycount) && ( mycount == trycount )) printf(" Ok\n");
        else printf("Wrong!\n");


      /* потом тестируем модуль кривой p */
       printf("p = %s\n", str = ak_mpzn_to_hexstr( ec->p, ec->size )); free( str );
       ak_mpzn_to_mpz( ec->p, ec->size, qp );

       /* собственно тестирование операции взятия остатка */
       count = 0; mycount = 0;
       for( j = 0; j < trycount; j++ ) {
          ak_mpzn_set_random( x, ec->size, generator );
          ak_mpzn_to_mpz( x, ec->size, xp );
          ak_mpzn_rem( r, x, ec->p, ec->size );
          mpz_mod( rp, xp, qp );

          ak_mpzn_to_mpz( r, ec->size, xp ); if( !mpz_cmp( rp, xp )) count++;
          ak_mpz_to_mpzn( rp, l, ec->size ); if( !ak_mpzn_cmp( r, l, ec->size )) mycount++;
       }
       printf(" %lu (%lu) tests passed successfully from %lu --- ", count, mycount, trycount );
       if( (count == trycount) && ( mycount == trycount )) printf(" Ok\n");
        else printf("Wrong!\n");

     /* теперь тест на скорость */
       ak_mpzn_set_random( x, ec->size, generator );
       ak_mpzn_to_mpz( x, ec->size, xp );

       tmr = clock();
       for( j = 0; j < trycount; j++ ) {
          ak_mpzn_rem( r, x, ec->p, ec->size );
          ak_mpzn_add( x, r, ec->p, ec->size );
       }
       tmr = clock() - tmr;
       printf("x = %s\n", str = ak_mpzn_to_hexstr( x, ec->size ));
       printf(" mpzn time:  %.3fs\n", ((double) tmr) / ((double) CLOCKS_PER_SEC));

       tmr = clock();
       for( j = 0; j < trycount; j++ ) {
          mpz_mod( rp, xp, qp );
          mpz_add( xp, rp, qp );
       }
       tmr = clock() - tmr;
       printf("x = "); mpz_out_str( stdout, 16, xp ); printf("\n");
       printf(" gmp time:   %.3fs\n", ((double) tmr) / ((double) CLOCKS_PER_SEC));

       ec = ak_wcurve_delete( ec );
       printf("\n");
     }
  }

 mpz_clear( xp );
 mpz_clear( rp );
 mpz_clear( qp );

 generator = ak_random_delete( generator );
 return ak_libakrypt_destroy();
}
