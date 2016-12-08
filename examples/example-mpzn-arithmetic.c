 #include <stdio.h>
 #include <libakrypt.h>
 #include <ak_mpzn.h>
 #include <ak_curves.h>
 #include <ak_buffer.h>
 #include <ak_parameters.h>
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


/* ----------------------------------------------------------------------------------------------- */
/* тест для операции сложения чисел */
 void add_test( size_t count )
{
  size_t i = 0, val = 0;
  mpz_t xm, ym, zm, tm;
  ak_mpzn512 x, y, z;
  ak_random generator = ak_random_new_lcg();
  mpz_init(xm);
  mpz_init(ym);
  mpz_init(zm);
  mpz_init(tm);

  for( i = 0; i < count; i++ ) {
    memset( x, 0, ak_mpzn512_size*sizeof(ak_uint64));
    memset( y, 0, ak_mpzn512_size*sizeof(ak_uint64));
    memset( z, 0, ak_mpzn512_size*sizeof(ak_uint64));
    ak_mpzn_set_random( x, ak_mpzn256_size, generator );
    ak_mpzn_set_random( y, ak_mpzn256_size, generator );
    ak_mpzn_to_mpz( x, ak_mpzn256_size, xm );
    ak_mpzn_to_mpz( y, ak_mpzn256_size, ym );

    z[ak_mpzn256_size] = ak_mpzn_add( z, x, y, ak_mpzn256_size );

    ak_mpzn_to_mpz( z, ak_mpzn512_size, zm );
    mpz_add( tm, xm, ym );

    if( mpz_cmp(tm, zm) == 0 ) val++;
  }
  printf(" correct additions %ld from %ld\n", val, count );
  mpz_clear(tm);
  mpz_clear(zm);
  mpz_clear(ym);
  mpz_clear(xm);
  generator = ak_random_delete( generator );
}

/* ----------------------------------------------------------------------------------------------- */
/* тест для операции сложения чисел */
 void sub_test( size_t count )
{
  int res = 0;
  size_t i = 0, val = 0, zerocnt = 0, limbwrong = 0;
  mpz_t xm, ym, zm, tm;
  ak_mpzn256 x, y, z;
  ak_uint64 limb = 0;
  ak_random generator = ak_random_new_lcg();
  mpz_init(xm);
  mpz_init(ym);
  mpz_init(zm);
  mpz_init(tm);

  for( i = 0; i < count; i++ ) {
     memset( x, 0, ak_mpzn256_size*sizeof(ak_uint64));
     memset( y, 0, ak_mpzn256_size*sizeof(ak_uint64));
     memset( z, 0, ak_mpzn256_size*sizeof(ak_uint64));
     ak_mpzn_set_random( x, ak_mpzn256_size, generator );
     ak_mpzn_set_random( y, ak_mpzn256_size, generator );
     ak_mpzn_to_mpz( x, ak_mpzn256_size, xm );
     ak_mpzn_to_mpz( y, ak_mpzn256_size, ym );

     res = ak_mpzn_cmp( x, y, ak_mpzn256_size );
     if( res  == 1 ) {
       if((limb = ak_mpzn_sub( z, x, y, ak_mpzn256_size )) != 0 ) limbwrong++;
       ak_mpzn_to_mpz( z, ak_mpzn256_size, zm );
       mpz_sub( tm, xm, ym );
     } else {
              if( !res ) zerocnt++;
              if(( limb = ak_mpzn_sub( z, y, x, ak_mpzn256_size )) != 0 ) limbwrong++;
              ak_mpzn_to_mpz( z, ak_mpzn256_size, zm );
              mpz_sub( tm, ym, xm );
            }

     if( mpz_cmp(tm, zm) == 0 ) val++;
  }
  printf(" correct substractions %ld from %ld (with %ld zeroes and %ld errors)\n",
                                                                   val, count, zerocnt, limbwrong );
  mpz_clear(tm);
  mpz_clear(zm);
  mpz_clear(ym);
  mpz_clear(xm);
  generator = ak_random_delete( generator );
}

/* ----------------------------------------------------------------------------------------------- */
/* тест для операции умножения чисел */
 void mul_test( size_t count )
{
  size_t i = 0, val = 0;
  mpz_t xm, ym, zm, tm;
  ak_mpzn256 x, y;
  ak_mpzn512 z;
  ak_random generator = ak_random_new_lcg();
  mpz_init(xm);
  mpz_init(ym);
  mpz_init(zm);
  mpz_init(tm);

  for( i = 0; i < count; i++ ) {
    /* обнуляем данные */
    memset( x, 0, ak_mpzn256_size*sizeof(ak_uint64));
    memset( y, 0, ak_mpzn256_size*sizeof(ak_uint64));
    memset( z, 0, ak_mpzn512_size*sizeof(ak_uint64));
    /* генерим случайные значения и копируем их в mpz */
    ak_mpzn_set_random( x, ak_mpzn256_size, generator );
    ak_mpzn_set_random( y, ak_mpzn256_size, generator );

    ak_mpzn_to_mpz( x, ak_mpzn256_size, xm );
    ak_mpzn_to_mpz( y, ak_mpzn256_size, ym );
    ak_mpzn_mul( z, x, y, ak_mpzn256_size );

    ak_mpzn_to_mpz( z, ak_mpzn512_size, zm );
    mpz_mul( tm, xm, ym );
    if( mpz_cmp(tm, zm) == 0 ) val++;
  }
  printf(" correct multiplications %ld from %ld\n", val, count );
  mpz_clear(tm);
  mpz_clear(zm);
  mpz_clear(ym);
  mpz_clear(xm);
  generator = ak_random_delete( generator );
}

/* ----------------------------------------------------------------------------------------------- */
/* тест для операции умножения чисел */
 void mul_ui_test( size_t count )
{
  size_t i = 0, val = 0;
  mpz_t xm, zm, tm;
  ak_uint64 d = 0;
  ak_mpzn256 x;
  ak_mpzn512 z;
  ak_random generator = ak_random_new_lcg();
  mpz_init(xm);
  mpz_init(zm);
  mpz_init(tm);

  for( i = 0; i < count; i++ ) {
    /* обнуляем данные */
    memset( x, 0, ak_mpzn256_size*sizeof(ak_uint64));
    memset( z, 0, ak_mpzn512_size*sizeof(ak_uint64));

    /* генерим случайные значения и копируем их в mpz */
    ak_mpzn_set_random( x, ak_mpzn256_size, generator );
    while( d == 0 ) d = ak_random_uint64( generator );

    ak_mpzn_to_mpz( x, ak_mpzn256_size, xm );
    z[ak_mpzn256_size] = ak_mpzn_mul_ui( z, x, ak_mpzn256_size, d );

    ak_mpzn_to_mpz( z, ak_mpzn512_size, zm );
    mpz_mul_ui( tm, xm, d );
    if( mpz_cmp(tm, zm) == 0 ) val++;
  }
  printf(" correct unsigned int multiplications %ld from %ld\n", val, count );
  mpz_clear(tm);
  mpz_clear(zm);
  mpz_clear(xm);
  generator = ak_random_delete( generator );
}


/* ----------------------------------------------------------------------------------------------- */
/* тест для операции умножения чисел */
 void add_montgomery_test( size_t count )
{
  size_t i = 0, val = 0;
  mpz_t xm, ym, zm, tm, pm;
  ak_mpzn256 x, y, z, p;
  ak_random generator = ak_random_new_lcg();
  char *str = NULL;
  clock_t tmr;

  mpz_init(xm);
  mpz_init(ym);
  mpz_init(zm);
  mpz_init(tm);
  mpz_init(pm);

  ak_mpzn_set_hexstr( p,
             ak_mpzn256_size, "80009F186DB88559655ED5580333E4E36887A2BB76B1462F43B2B6DD1626C321" );
  ak_mpzn_to_mpz( p, ak_mpzn256_size, pm );
  printf( " p = %s\n", str = ak_mpzn_to_hexstr( p, ak_mpzn256_size )); free(str);

  for( i = 0; i < count; i++ ) {
     ak_mpzn_set_random_modulo( x, p, ak_mpzn256_size, generator );
     ak_mpzn_set_random_modulo( y, p, ak_mpzn256_size, generator );
     ak_mpzn_to_mpz( x, ak_mpzn256_size, xm );
     ak_mpzn_to_mpz( y, ak_mpzn256_size, ym );
     // z <- (x+y)
     ak_mpzn_add_montgomery( z, x, y, p, ak_mpzn256_size );
     ak_mpzn_to_mpz( z, ak_mpzn256_size, zm );

     mpz_add( tm, xm, ym );
     mpz_mod( tm, tm, pm );
     if( mpz_cmp(tm, zm) == 0 ) val++;
  }
  printf(" correct montgomery additions %ld from %ld\n", val, count );

  // speed test
  ak_mpzn_set_random_modulo( x, p, ak_mpzn256_size, generator );
  ak_mpzn_set_random_modulo( y, p, ak_mpzn256_size, generator );
  ak_mpzn_to_mpz( x, ak_mpzn256_size, xm );
  ak_mpzn_to_mpz( y, ak_mpzn256_size, ym );

  tmr = clock();
  for( i = 0; i < count; i++ ) {
     ak_mpzn_add_montgomery( z, x, y, p, ak_mpzn256_size );
     ak_mpzn_add_montgomery( x, y, z, p, ak_mpzn256_size );
     ak_mpzn_add_montgomery( y, z, x, p, ak_mpzn256_size );
  }
  tmr = clock() - tmr;
  printf(" mpzn time: %.3fs\n", ((double) tmr) / ((double) CLOCKS_PER_SEC));
  printf(" y = %s\n", str = ak_mpzn_to_hexstr( y, ak_mpzn256_size )); free(str);

  tmr = clock();
  for( i = 0; i < count; i++ ) {
     mpz_add( zm, xm, ym ); // mpz_mod( zm, zm, pm ); так быстрее ))
     mpz_add( xm, ym, zm ); // mpz_mod( xm, xm, pm );
     mpz_add( ym, zm, xm ); mpz_mod( ym, ym, pm );
  }
  tmr = clock() - tmr;
  printf(" gmp time:  %.3fs\n", ((double) tmr) / ((double) CLOCKS_PER_SEC));
  printf(" y = "); mpz_out_str( stdout, 16, ym ); printf("\n");

  mpz_clear(pm);
  mpz_clear(tm);
  mpz_clear(zm);
  mpz_clear(ym);
  mpz_clear(xm);

  generator = ak_random_delete( generator );
}


/* ----------------------------------------------------------------------------------------------- */
/* тест для операции умножения чисел */
 void mul_montgomery_test( size_t count )
{
  size_t i = 0, errors_gmp = 0, val = 0;
  mpz_t xm, ym, zm, tm, pm, rm, gm, sm, um, nm;
  ak_mpzn256 x, y, n, p;
  ak_mpzn512 z;
  ak_random generator = ak_random_new_lcg();
  char *str = NULL;
  clock_t tmr;

  mpz_init(xm);
  mpz_init(ym);
  mpz_init(zm);
  mpz_init(tm);
  mpz_init(pm);
  mpz_init(rm);
  mpz_init(gm);
  mpz_init(sm);
  mpz_init(um);
  mpz_init(nm);

  mpz_set_str( pm, "8000000000000000000000000000000000000000000000000000000000000431", 16 );
  mpz_set_ui( rm, 2 ); mpz_pow_ui( rm, rm, 256 );
  mpz_gcdext( gm, sm, nm, rm, pm ); // sm*rm + nm*pm = 1 = gm
  mpz_neg( nm, nm );

 // вычисляем параметры
  printf(" r = "); mpz_out_str( stdout, 16, rm ); printf("\n");
  printf(" p =  "); mpz_out_str( stdout, 16, pm ); printf("\n");
  printf(" n =  "); mpz_out_str( stdout, 16, nm ); printf(" = -p^{-1} (mod r)\n");
  printf(" s =  "); mpz_out_str( stdout, 16, sm ); printf(" = r^{-1} (mod p)\n");
  mpz_mul( gm, rm, sm ); mpz_mul( tm, nm, pm ); mpz_sub( gm, gm, tm );
  printf(" sr - np = "); mpz_out_str( stdout, 16, gm ); printf("\n");
  mpz_mod( tm, rm, pm ); mpz_mul( tm, tm, tm ); mpz_mod( tm, tm, pm );
  printf(" r^2 = "); mpz_out_str( stdout, 16, tm ); printf(" (mod p)\n");

  ak_mpz_to_mpzn( nm, n, ak_mpzn256_size );
  ak_mpz_to_mpzn( pm, p, ak_mpzn256_size );

 // основной цикл проверок
  for( i = 0; i < count; i++ ) {
     ak_mpzn_set_random_modulo( x, p, ak_mpzn256_size, generator );
     ak_mpzn_set_random_modulo( y, p, ak_mpzn256_size, generator );
     ak_mpzn_to_mpz( x, ak_mpzn256_size, xm );
     ak_mpzn_to_mpz( y, ak_mpzn256_size, ym );

     // тестовый пример для умножения: результат x*y*r-1
     mpz_mul( zm, xm, ym ); mpz_mul( zm, zm, sm ); mpz_mod( zm, zm, pm );

     // теперь то же в форме Монтгомери
     mpz_mul( tm, xm, ym );
     mpz_mul( um, tm, nm );
     mpz_mod( um, um, rm );
     mpz_mul( um, um, pm );
     mpz_add( um, um, tm );
     mpz_div_2exp( um, um, 256 );
     if( mpz_cmp( um, pm ) == 1 ) mpz_sub( um, um, pm );
     if( mpz_cmp( um, zm ) != 0 ) errors_gmp++;

     ak_mpzn_mul_montgomery( z, x, y, p, n[0], ak_mpzn256_size );
     ak_mpzn_to_mpz( z, ak_mpzn256_size, zm );
     if( mpz_cmp( um, zm ) == 0 ) val++;
  }
  printf(" correct montgomery multiplications %ld from %ld with %ld gmp errors\n", val, count, errors_gmp );

  // speed test
  ak_mpzn_set_random_modulo( x, p, ak_mpzn256_size, generator );
  ak_mpzn_set_random_modulo( y, p, ak_mpzn256_size, generator );
  ak_mpzn_to_mpz( x, ak_mpzn256_size, xm );
  ak_mpzn_to_mpz( y, ak_mpzn256_size, ym );

  tmr = clock();
  for( i = 0; i < count; i++ ) {
     ak_mpzn_mul_montgomery( z, x, y, p, n[0], ak_mpzn256_size );
     ak_mpzn_mul_montgomery( x, y, z, p, n[0], ak_mpzn256_size );
     ak_mpzn_mul_montgomery( y, z, x, p, n[0], ak_mpzn256_size );
  }
  tmr = clock() - tmr;
  printf(" mpzn time: %.3fs [", ((double) tmr) / ((double) CLOCKS_PER_SEC));
  printf("y = %s]\n", str = ak_mpzn_to_hexstr( y, ak_mpzn256_size )); free(str);

  ak_mpz_to_mpzn( xm, x, ak_mpzn256_size );
  ak_mpz_to_mpzn( ym, y, ak_mpzn256_size );
  ak_mpz_to_mpzn( zm, z, ak_mpzn256_size );


  tmr = clock();
  for( i = 0; i < count; i++ ) {
     mpz_mul( zm, xm, ym ); mpz_mul( zm, zm, sm ); mpz_mod( zm, zm, pm );
     mpz_mul( xm, ym, zm ); mpz_mul( xm, xm, sm ); mpz_mod( xm, xm, pm );
     mpz_mul( ym, zm, xm ); mpz_mul( ym, ym, sm ); mpz_mod( ym, ym, pm );
  }
  tmr = clock() - tmr;
  printf(" gmp time:  %.3fs [", ((double) tmr) / ((double) CLOCKS_PER_SEC));
  printf("y = "); mpz_out_str( stdout, 16, ym ); printf("]\n");

  tmr = clock();
  for( i = 0; i < count; i++ ) {
     mpz_mul( zm, xm, ym ); mpz_mod( zm, zm, pm );
     mpz_mul( xm, ym, zm ); mpz_mod( xm, xm, pm );
     mpz_mul( ym, zm, xm ); mpz_mod( ym, ym, pm );
  }
  tmr = clock() - tmr;
  printf(" gmp time:  %.3fs [only multiplication with modulo reduction]\n", ((double) tmr) / ((double) CLOCKS_PER_SEC));

  mpz_clear(nm);
  mpz_clear(gm);
  mpz_clear(sm);
  mpz_clear(um);
  mpz_clear(rm);
  mpz_clear(pm);
  mpz_clear(tm);
  mpz_clear(zm);
  mpz_clear(ym);
  mpz_clear(xm);
  generator = ak_random_delete( generator );
}

/* ----------------------------------------------------------------------------------------------- */
/* тест для операции возведения в степень */
 void modpow_montgomery_test( size_t count )
{
   size_t i = 0, val = 0;
   mpz_t xm, ym, zm, tm, pm, rm, gm, sm, um, nm;
   ak_mpzn256 x, y, n;
   ak_random generator = ak_random_new_lcg();
   clock_t tmr;
   ak_wcurve ec = ak_wcurve_new(( const ak_wcurve_params) &wcurve_GOST );
   count /= 10;

   mpz_init(xm);
   mpz_init(ym);
   mpz_init(zm);
   mpz_init(tm);
   mpz_init(pm);
   mpz_init(rm);
   mpz_init(gm);
   mpz_init(sm);
   mpz_init(um);
   mpz_init(nm);

   ak_mpzn_to_mpz( ec->p, ec->size, pm );
   printf(" p   = "); mpz_out_str( stdout, 16, pm ); printf("\n");

   ak_mpzn_set_ui( y, ec->size, 1 );
   printf(" please wait: "); fflush( stdout );

   for( i = 0; i < count; i++ ) {
     ak_mpzn_set_random_modulo( x, ec->p, ec->size, generator );
     ak_mpzn_to_mpz( x, ec->size, xm );
     ak_mpzn_set_random_modulo( n, ec->p, ec->size, generator );
     ak_mpzn_to_mpz( n, ec->size, nm );

     // тест для mpz
     mpz_powm( xm, xm, nm, pm );

     // тест для mpzn
     ak_mpzn_mul_montgomery( x, x, ec->r2, ec->p, ec->n, ec->size );
     ak_mpzn_modpow_montgomery( x, x, n, ec->p, ec->n, ec->size );
     ak_mpzn_mul_montgomery( x, x, y, ec->p, ec->n, ec->size );

     ak_mpzn_to_mpz( x, ec->size, um );
     if( mpz_cmp( um, xm ) == 0 ) val++;
     if( i%(count/50) == 0 ) { printf("."); fflush(stdout); }
   }
   printf("\n correct modular exponentiation in montgomery form: %ld from %ld\n", val, count );

   printf(" speed test: "); fflush( stdout );
   tmr = clock();
   for( i = 0; i < count; i++ ) ak_mpzn_modpow_montgomery( x, x, n, ec->p, ec->n, ec->size );
   tmr = clock() - tmr;
   printf(" mpzn time: %.3fs, ", ((double) tmr) / ((double) CLOCKS_PER_SEC));

   tmr = clock();
   for( i = 0; i < count; i++ ) mpz_powm( xm, xm, nm, pm );
   tmr = clock() - tmr;
   printf(" gmp time:  %.3fs\n\n", ((double) tmr) / ((double) CLOCKS_PER_SEC));

   mpz_clear(nm);
   mpz_clear(gm);
   mpz_clear(sm);
   mpz_clear(um);
   mpz_clear(rm);
   mpz_clear(pm);
   mpz_clear(tm);
   mpz_clear(zm);
   mpz_clear(ym);
   mpz_clear(xm);
   ec = ak_wcurve_delete( ec );
   generator = ak_random_delete( generator );
}

/* ----------------------------------------------------------------------------------------------- */
 void print_wcurve( ak_wcurve ec )
{
  int i = 0;
  char *str = NULL;

  printf("elliptic curve (reverse array = starts from high bytes, ends to low):\n");
  // A
  printf(" a = %s [reverse byte array]\n a = ",
     str = ak_ptr_to_hexstr( ec->a, ec->size*sizeof(ak_uint64), ak_true )); free(str);
  for( i = 0; i < ec->size; i++ ) printf("%lx ", ec->a[i]);
  printf("[ak_uint64 array]\n\n");
  // B
  printf(" b = %s [reverse byte array]\n b = ",
     str = ak_ptr_to_hexstr( ec->b, ec->size*sizeof(ak_uint64), ak_true )); free(str);
  for( i = 0; i < ec->size; i++ ) printf("%lx ", ec->b[i]);
  printf("[ak_uint64 array]\n\n");
  // P
  printf(" p = %s [reverse byte array]\n p = ",
     str = ak_ptr_to_hexstr( ec->p, ec->size*sizeof(ak_uint64), ak_true )); free(str);
  for( i = 0; i < ec->size; i++ ) printf("%lx ", ec->p[i]);
  printf("[ak_uint64 array]\n\n");
  // Q
  printf(" q = %s [reverse byte array]\n q = ",
     str = ak_ptr_to_hexstr( ec->q, ec->size*sizeof(ak_uint64), ak_true )); free(str);
  for( i = 0; i < ec->size; i++ ) printf("%lx ", ec->q[i]);
  printf("[ak_uint64 array]\n\n");
  // R1
  printf("r1 = %s [reverse byte array]\nr1 = ",
     str = ak_ptr_to_hexstr( ec->r1, ec->size*sizeof(ak_uint64), ak_true )); free(str);
  for( i = 0; i < ec->size; i++ ) printf("%lx ", ec->r1[i]);
  printf("[ak_uint64 array]\n\n");
  // R2
  printf("r2 = %s [reverse byte array]\nr2 = ",
     str = ak_ptr_to_hexstr( ec->r2, ec->size*sizeof(ak_uint64), ak_true )); free(str);
  for( i = 0; i < ec->size; i++ ) printf("%lx ", ec->r2[i]);
  printf("[ak_uint64 array]\n\n");
}

/* ----------------------------------------------------------------------------------------------- */
 void print_wpoint( ak_wpoint wp, ak_wcurve ec )
{
  int i = 0;
  char *str = NULL;

  printf("point of elliptic curve:\n");
  // X
  printf(" x = %s [reverse byte array]\n x = ",
     str = ak_ptr_to_hexstr( wp->x, ec->size*sizeof(ak_uint64), ak_true )); free(str);
  for( i = 0; i < ec->size; i++ ) printf("%lx ", wp->x[i]);
  printf("[ak_uint64 array]\n\n");
  // Y
  printf(" y = %s [reverse byte array]\n y = ",
     str = ak_ptr_to_hexstr( wp->y, ec->size*sizeof(ak_uint64), ak_true )); free(str);
  for( i = 0; i < ec->size; i++ ) printf("%lx ", wp->y[i]);
  printf("[ak_uint64 array]\n\n");
  // X
  printf(" z = %s [reverse byte array]\n z = ",
     str = ak_ptr_to_hexstr( wp->z, ec->size*sizeof(ak_uint64), ak_true )); free(str);
  for( i = 0; i < ec->size; i++ ) printf("%lx ", wp->z[i]);
  printf("[ak_uint64 array]\n\n");
}

/* ----------------------------------------------------------------------------------------------- */
/* тест для операций на эллиптических кривых */
 void wcurve_test( size_t count )
{
  char *str = NULL;
  ak_wcurve ec = ak_wcurve_new(( const ak_wcurve_params) &wcurve_GOST );
  ak_wpoint wp = ak_wpoint_new(( const ak_wcurve_params) &wcurve_GOST );
  mpz_t am, bm, pm, r2m, tm, sm, rm, gm;

  mpz_init(am);
  mpz_init(bm);
  mpz_init(pm);
  mpz_init(r2m);
  mpz_init(tm);
  mpz_init(sm);
  mpz_init(rm);
  mpz_init(gm);

  print_wcurve(ec);
  if( ak_wcurve_is_ok(ec)) printf(" curve is Ok\n");

  ak_mpzn256 d;
  ak_mpzn_set_wcurve_discriminant( d, ec );
  printf(" (4a^3+27b^2) (mod p)  = %s [reverse byte array]\n",
            str = ak_ptr_to_hexstr( d, ec->size*sizeof(ak_uint64), ak_true )); free(str);

  mpz_set_str( am, wcurve_GOST.ca, 16 );
  mpz_set_str( bm, wcurve_GOST.cb, 16 );
  mpz_set_str( pm, wcurve_GOST.cp, 16 );
  mpz_sub_ui( rm, pm, 16 );
  mpz_mul_ui( tm, am, 4 );
  mpz_mul( tm, tm, am );
  mpz_mul( tm, tm, am );
  mpz_mul_ui( sm, bm, 27 );
  mpz_mul( sm, sm, bm );
  mpz_add( tm, tm, sm );
  mpz_mul( tm, tm, rm );
  mpz_mod( tm, tm, pm );
  printf(" Discriminant (mod p)  = "); mpz_out_str( stdout, 16, tm ); printf("\n\n");

  print_wpoint( wp, ec );
  if( ak_wpoint_is_ok( wp, ec )) printf(" point is Ok\n"); else printf(" point is wrong\n");

  ak_wpoint_double( wp, ec );


  mpz_clear( gm );
  mpz_clear( rm );
  mpz_clear( am );
  mpz_clear( bm );
  mpz_clear( pm );
  mpz_clear( r2m );
  mpz_clear( tm );
  mpz_clear( sm );

  wp = ak_wpoint_delete( wp );
  ec = ak_wcurve_delete( ec );
}

/* ----------------------------------------------------------------------------------------------- */
/* основная тестирующая программа */
 int main( void )
{
  size_t count = 1000000;

 /*
  printf(" - ak_mpzn_add() function test\n"); add_test( count );
  printf(" - ak_mpzn_sub() function test\n"); sub_test( count );
  printf(" - ak_mpzn_mul() function test\n"); mul_test( count );
  printf(" - ak_mpzn_mul_ui() function test\n"); mul_ui_test( count );
  printf("\n - ak_mpzn_add_montgomery() function test\n"); add_montgomery_test( count );
  printf("\n - ak_mpzn_mul_montgomery() function test\n"); mul_montgomery_test( count );
  printf(" - ak_mpzn_modpow_montgomery() function test\n"); modpow_montgomery_test( count );
 */
  printf("\n - wcurve class test\n"); wcurve_test( count );

 return 0;
}
