 #include <stdio.h>
 #include <ak_bckey.h>

/* ----------------------------------------------------------------------------------------------- */
 static void ak_gf128_mul_pcmulqdq( ak_pointer z, ak_pointer a, ak_pointer b )
{
 __m128i am = *((__m128i *) a);
 __m128i bm = *((__m128i *) b);

 /* умножение */
 __m128i cm = _mm_clmulepi64_si128( am, bm, 0x00 ); // c = a0*b0
 __m128i dm = _mm_clmulepi64_si128( am, bm, 0x11 ); // d = a1*b1
 __m128i em = _mm_clmulepi64_si128( am, bm, 0x10 ); // e = a0*b1
 __m128i fm = _mm_clmulepi64_si128( am, bm, 0x01 ); // f = a1*b0

 /* приведение */
  ak_uint64 x3 = dm[1];
  ak_uint64 D = dm[0] ^ em[1] ^ fm[1] ^ (x3 >> 63) ^ (x3 >> 62) ^ (x3 >> 57);

  cm[0] ^=  D ^ (D << 1) ^ (D << 2) ^ (D << 7);
  cm[1] ^=  em[0] ^ fm[0] ^ x3 ^ (x3 << 1) ^ (D >> 63) ^ (x3 << 2) ^ (D >> 62) ^ (x3 << 7) ^ (D >> 57);

  ((ak_uint64 *)z)[0] = cm[0];
  ((ak_uint64 *)z)[1] = cm[1];
}

/* ----------------------------------------------------------------------------------------------- */
 static void ak_gf128_mul( ak_pointer z, ak_pointer x, ak_pointer y )
{
 int i = 0, n = 0;
 ak_uint64 t, s0 = ((ak_uint64 *)x)[0], s1 = ((ak_uint64 *)x)[1];

 /* обнуляем результирующее значение */
 ((ak_uint64 *)z)[0] = 0; ((ak_uint64 *)z)[1] = 0;

 /* вычисляем  произведение для младшей половины */
 t = ((ak_uint64 *)y)[0];
 for( i = 0; i < 64; i++ ) {

   if( t&0x1 ) { ((ak_uint64 *)z)[0] ^= s0; ((ak_uint64 *)z)[1] ^= s1; }
   t >>= 1;
   n = s1 >> 63;
   s1 <<= 1; s1 ^= ( s0 >> 63 ); s0 <<= 1;
   if( n ) s0 ^= 0x87;
 }

 /* вычисляем  произведение для старшей половины */
 t = ((ak_uint64 *)y)[1];
 for( i = 0; i < 63; i++ ) {

   if( t&0x1 ) { ((ak_uint64 *)z)[0] ^= s0; ((ak_uint64 *)z)[1] ^= s1; }
   t >>= 1;
   n = s1 >> 63;
   s1 <<= 1; s1 ^= ( s0 >> 63 ); s0 <<= 1;
   if( n ) s0 ^= 0x87;
 }

 if( t&0x1 ) {
   ((ak_uint64 *)z)[0] ^= s0;
   ((ak_uint64 *)z)[1] ^= s1;
 }
}

/* ----------------------------------------------------------------------------------------------- */
 ak_bool mul_test( void )
{
 int i;
 char *str = NULL;

 ak_uint8 a8[16] = { 0x5d, 0x47, 0x53, 0x5d, 0x72, 0x6f, 0x74, 0x63, 0x65, 0x56, 0x74, 0x73, 0x65, 0x54, 0x5b, 0x7b };
 ak_uint8 b8[16] = { 0x5d, 0x6e, 0x6f, 0x72, 0x65, 0x75, 0x47, 0x5b, 0x29, 0x79, 0x61, 0x68, 0x53, 0x28, 0x69, 0x48 };

 ak_uint128 a = { .q = { 0x63746f725d53475d, 0x7b5b546573745665 }};
 ak_uint128 b = { .q = { 0x5b477565726f6e5d, 0x4869285368617929 }};

 ak_uint64 val[2] = { 0x7e4e10da323506d2, 0x040229a09a5ed12e };
 ak_uint8 out[16], out2[16];

 // сравниваем данные
 if( !ak_ptr_is_equal( a8, a.q, 16 )) return ak_false;
 if( !ak_ptr_is_equal( b8, b.q, 16 )) return ak_false;

 // примеры из white paper (pcmulqdq)
 // a = 0x7b5b54657374566563746f725d53475d
 // b =  0x48692853686179295b477565726f6e5d
 // GFMUL128 (a, b) = 0x40229a09a5ed12e7e4e10da323506d2
 ak_gf128_mul( out, &a, &b );
 ak_gf128_mul_pcmulqdq( out2, &a, &b );
 if( !ak_ptr_is_equal( out, out2, 16 )) return ak_false;
 if( !ak_ptr_is_equal( out, val, 16 )) return ak_false;

 printf("a:   %s\n", str = ak_ptr_to_hexstr( &a, 16, ak_true )); free( str );
 printf("b:   %s\n", str = ak_ptr_to_hexstr( &b, 16, ak_true )); free( str );
 printf("a*b: %s\n\n", str = ak_ptr_to_hexstr( &out2, 16, ak_true )); free( str );

 for( i = 0; i < 9; i++ ) {
   a.q[0] = b.q[1]; a.q[1] = b.q[0];
   memcpy( b.b, out, 16 );

   printf("a:   %s\n", str = ak_ptr_to_hexstr( &a, 16, ak_true )); free( str );
   printf("b:   %s\n", str = ak_ptr_to_hexstr( &b, 16, ak_true )); free( str );

   ak_gf128_mul( out, &a, &b );
   ak_gf128_mul_pcmulqdq( out2, &a, &b );
   if( !ak_ptr_is_equal( out, out2, 16 )) return ak_false;
   printf("a*b: %s\n\n", str = ak_ptr_to_hexstr( &out2, 16, ak_true )); free( str );
 }

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
 void aead( ak_bckey keyEncryption, ak_bckey keyAuthentication, ak_pointer iv, size_t iv_size,
        ak_pointer adata, size_t adata_size, ak_pointer pdata, size_t pdata_size, ak_pointer cdata )
{
  size_t i = 0, j = 0;
  char *str = NULL;

  size_t bsize = keyEncryption->ivector.size,
         blocks = pdata_size / bsize,
         tail = pdata_size - blocks*bsize;

  size_t absize = keyAuthentication->ivector.size,
         ablocks = adata_size / absize,
         atail = adata_size - ablocks*absize;


  ak_uint8 ivector[16], z[16], h[16], y[16], temp[16];
  ak_uint64 mulres[2], e[2], icode[2] = { 0, 0 };

  ak_uint8 *a = (ak_uint8 *) adata;
  ak_uint64 *p = (ak_uint64 *) pdata;
  ak_uint64 *c = (ak_uint64 *) cdata;

 /* вывод информации */
  printf("Encryption key: %s (%lu bytes per block)\n", keyEncryption->key.oid->name, bsize );
  printf("Authentication key: %s (%lu bytes per block)\n\n", keyAuthentication->key.oid->name, absize );

  printf("Initial vector:\n   iv: %s\n\n", str = ak_ptr_to_hexstr( iv, iv_size, ak_true )); free( str );

  printf("Plain data:  (%lu bytes)\n", pdata_size );
  for( i = 0; i < blocks; i++ ) {
     printf(" p[%lu]: %s\n", i+1,
        str = ak_ptr_to_hexstr( ((ak_uint8 *)pdata)+i*bsize, bsize, ak_true )); free( str );
  }
  if( tail ) {
     printf(" p[%lu]: %s  (%lu bytes)\n", blocks+1,
        str = ak_ptr_to_hexstr( ((ak_uint8 *)pdata)+blocks*bsize, tail, ak_true ), tail);
        free( str );
  }

 /* вывод информации */
  printf("\nAdditional data:  (%lu bytes)\n", adata_size );
  for( i = 0; i < ablocks; i++ ) {
     printf(" a[%lu]: %s\n", i+1,
        str = ak_ptr_to_hexstr( ((ak_uint8 *)adata)+i*absize, absize, ak_true )); free( str );
  }
  if( atail ) {
     printf(" a[%lu]: %s  (%lu bytes)\n", ablocks+1,
        str = ak_ptr_to_hexstr( ((ak_uint8 *)adata)+ablocks*absize, atail, ak_true ), atail);
        free( str );
  }


 /* Начальные значения счетчиков */
  memset( ivector, 0, 16 );
  memcpy( ivector, iv, absize ); /* копируем нужное количество байт */
  ivector[absize-1] = (( ivector[absize-1] << 1 ) >> 1 ) ^ 0x80; // принудительно устанавливаем старший бит в 1

  printf("\nFirst phase (additional data hashing)\n");
  printf("     iv: %s\n\n", str = ak_ptr_to_hexstr( ivector, absize, ak_true )); free( str );
  keyAuthentication->encrypt( &keyAuthentication->key, ivector, z );

  for( i = 0; i < ablocks; i++ ) {
     printf("   z[%lu]: %s\n", i+1, str = ak_ptr_to_hexstr( z, absize, ak_true )); free( str );
     printf("               "); for( j = 0; j < absize/2; j++ ) printf(" ");
     printf("-^-\n");

     keyAuthentication->encrypt( &keyAuthentication->key, z, h );
     printf("   h[%lu]: %s\n", i+1, str = ak_ptr_to_hexstr( h, absize, ak_true )); free( str );
     printf("   a[%lu]: %s\n", i+1, str = ak_ptr_to_hexstr( a+absize*i, absize, ak_true )); free( str );

     ak_gf128_mul_pcmulqdq( mulres, h, a+absize*i );
     printf(" h*a[%lu]: %s\n", i+1, str = ak_ptr_to_hexstr( mulres, absize, ak_true )); free( str );

     icode[0] ^= mulres[0]; icode[1] ^= mulres[1];
     printf(" sum[%lu]: %s\n", i+1, str = ak_ptr_to_hexstr( icode, absize, ak_true )); free( str );

     ((ak_uint32 *)(z+(absize/2)))[0]++;
     printf("\n");
  }

 /* обрабатываем хвост */
  if( atail ) {
     printf("   z[%u]: %s\n", 3, str = ak_ptr_to_hexstr( z, absize, ak_true )); free( str );
     printf("               "); for( j = 0; j < absize/2; j++ ) printf(" ");
     printf("-^-\n");

     keyAuthentication->encrypt( &keyAuthentication->key, z, h );
     printf("   h[%u]: %s\n", 3, str = ak_ptr_to_hexstr( h, absize, ak_true )); free( str );

     memset( temp, 0, 16 );
     memcpy( temp+absize-atail, a+absize*ablocks, atail );
     printf("   a[%u]: %s\n", 3, str = ak_ptr_to_hexstr( temp, absize, ak_true )); free( str );

     ak_gf128_mul_pcmulqdq( mulres, h, temp );
     printf(" h*a[%u]: %s\n", 3, str = ak_ptr_to_hexstr( mulres, absize, ak_true )); free( str );

     icode[0] ^= mulres[0]; icode[1] ^= mulres[1];
     printf(" sum[%u]: %s\n", 3, str = ak_ptr_to_hexstr( icode, absize, ak_true )); free( str );

     ((ak_uint32 *)(z+(absize/2)))[0]++;
     printf("\n");
  }

  printf("Second phase (encryption and hashing)\n");
  memset( ivector, 0, 16 );
  memcpy( ivector, iv, bsize ); /* копируем нужное количество байт */
  ivector[bsize-1] = (( ivector[bsize-1] << 1 ) >> 1 ); // принудительно устанавливаем старший бит в 0

  printf("     iv: %s\n\n", str = ak_ptr_to_hexstr( ivector, bsize, ak_true )); free( str );
  keyEncryption->encrypt( &keyEncryption->key, ivector, y );

  for( i = 0; i < blocks; i++ ) {
     printf("   z[%lu]: %s\n", i+ablocks+2, str = ak_ptr_to_hexstr( z, absize, ak_true )); free( str );
     printf("       "); for( j = 0; j < absize; j++ ) printf(" ");
     printf("-^-\n");

     keyAuthentication->encrypt( &keyAuthentication->key, z, h );
     printf("   h[%lu]: %s\n", i+ablocks+2, str = ak_ptr_to_hexstr( h, absize, ak_true )); free( str );

     printf("   y[%lu]: %s\n", i+1, str = ak_ptr_to_hexstr( y, bsize, ak_true )); free( str );
     printf("       "); for( j = 0; j < 2*bsize; j++ ) printf(" ");
     printf("-^-\n");

     keyEncryption->encrypt( &keyEncryption->key, y, e );
     printf("   e[%lu]: %s\n", i+1, str = ak_ptr_to_hexstr( e, bsize, ak_true )); free( str );
     printf("   p[%lu]: %s\n", i+1, str = ak_ptr_to_hexstr( p+i*2, bsize, ak_true )); free( str );

     c[i*2] = p[i*2] ^ e[0]; c[i*2+1] = p[i*2+1] ^ e[1];
     printf("   c[%lu]: %s\n", i+1, str = ak_ptr_to_hexstr( c+i*2, bsize, ak_true )); free( str );

     /* теперь умножение */
     ak_gf128_mul_pcmulqdq( mulres, h, c+i*2 );
     printf("       : %s <- h[%lu]*c[%lu]\n",
       str = ak_ptr_to_hexstr( mulres, absize, ak_true ), i+ablocks+2, i+1 ); free( str );

     icode[0] ^= mulres[0]; icode[1] ^= mulres[1];
     printf(" sum[%lu]: %s\n", i+ablocks+2, str = ak_ptr_to_hexstr( icode, absize, ak_true )); free( str );

     ((ak_uint32 *)(z+(absize/2)))[0]++;
     ((ak_uint32 *)y)[0]++;
     printf("\n");
  }

  if( tail ) {
     printf("   z[%u]: %s\n", 8, str = ak_ptr_to_hexstr( z, absize, ak_true )); free( str );
     printf("       "); for( j = 0; j < absize; j++ ) printf(" ");
     printf("-^-\n");

     keyAuthentication->encrypt( &keyAuthentication->key, z, h );
     printf("   h[%u]: %s\n", 8, str = ak_ptr_to_hexstr( h, absize, ak_true )); free( str );

     printf("   y[%u]: %s\n", 5, str = ak_ptr_to_hexstr( y, bsize, ak_true )); free( str );
     printf("       "); for( j = 0; j < 2*bsize; j++ ) printf(" ");
     printf("-^-\n");

     keyEncryption->encrypt( &keyEncryption->key, y, e );

     printf("   e[%u]: %s\n", 5, str = ak_ptr_to_hexstr( e, bsize, ak_true )); free( str );
     printf("   p[%u]: %s\n", 5, str = ak_ptr_to_hexstr( p+i*2, tail, ak_true )); free( str );

     for( j = 0; j < tail; j++ ) {
        ((ak_uint8 *)c)[bsize*blocks+j] =
               ((ak_uint8 *)p)[ blocks*bsize+j ] ^ ((ak_uint8* )e)[bsize-tail+j];
     }
     printf("   c[%u]: %s\n", 5, str = ak_ptr_to_hexstr( ((ak_uint8* )c)+bsize*blocks, tail, ak_true )); free( str );

     memset( temp, 0, 16 );
     memcpy( temp+(bsize-tail), ((ak_uint8 *)c)+bsize*blocks, tail );
     printf("  c'[%u]: %s\n", 5, str = ak_ptr_to_hexstr( temp, bsize, ak_true )); free( str );

     /* теперь умножение */
     ak_gf128_mul_pcmulqdq( mulres, h, temp );
     printf("       : %s <- h[%u]*c'[%u]\n",
       str = ak_ptr_to_hexstr( mulres, absize, ak_true ), 8, 5 ); free( str );

     icode[0] ^= mulres[0]; icode[1] ^= mulres[1];
     printf(" sum[%u]: %s\n", 8, str = ak_ptr_to_hexstr( icode, absize, ak_true )); free( str );

     ((ak_uint32 *)(z+(absize/2)))[0]++;
     ((ak_uint32 *)y)[0]++;
     printf("\n");
  } // tail


  printf("Finalize\n");

 /* теперь длины и шифрование */
     printf("   z[%u]: %s\n", 9, str = ak_ptr_to_hexstr( z, absize, ak_true )); free( str );
     printf("       "); for( j = 0; j < absize; j++ ) printf(" ");
     printf("-^-\n");

     keyAuthentication->encrypt( &keyAuthentication->key, z, h );
     printf("   h[%u]: %s\n", 9, str = ak_ptr_to_hexstr( h, absize, ak_true )); free( str );

     memset( temp, 0, 16 );
     ((ak_uint64 *)temp)[0] = pdata_size*8;
     ((ak_uint64 *)temp)[1] = adata_size*8;

     printf("   len(plain data): %ld bits (hex %lx)\n", pdata_size*8, pdata_size*8 );
     printf("   len(additional data): %ld bits (hex %lx)\n", adata_size*8, adata_size*8 );
     printf("    len: %s\n", str = ak_ptr_to_hexstr( temp, absize, ak_true )); free( str );

     /* теперь умножение */
     ak_gf128_mul_pcmulqdq( mulres, z, temp );
     printf("       : %s <- h[%u]*len\n",
       str = ak_ptr_to_hexstr( mulres, absize, ak_true ), 9); free( str );

     icode[0] ^= mulres[0]; icode[1] ^= mulres[1];
     printf(" sum[%u]: %s\n", 9, str = ak_ptr_to_hexstr( icode, absize, ak_true )); free( str );

    keyAuthentication->encrypt( &keyAuthentication->key, icode, ivector );

     printf("  icode: %s <- E(sum)\n", str = ak_ptr_to_hexstr( ivector, absize, ak_true )); free( str );
}

/* ----------------------------------------------------------------------------------------------- */




/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{

 ak_libakrypt_create( NULL );

 printf("Multiplication test:\n\n");
 if( mul_test( )) printf("Ok\n");
  else printf("Wrong\n");



 printf("\nEncryption:\n\n");

 struct bckey bkey;
 ak_uint8 testkey[32] = {
                     0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
                     0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

 /* открытый текст из ГОСТ Р 34.13-2015, приложение А.1, подлежащий зашифрованию */
  ak_uint64 p[9] = {
    0xffeeddccbbaa9988, 0x1122334455667700, 0x8899aabbcceeff0a, 0x0011223344556677,
    0x99aabbcceeff0a00, 0x1122334455667788, 0xaabbcceeff0a0011, 0x2233445566778899, 0xaabbcc };

 /* шифртекст */
  ak_uint64 c[9];

 /* асссоциированные данные */
  ak_uint64 a[6] = {
    0x0101010101010101, 0x0202020202020202, 0x0303030303030303, 0x0404040404040404,
    0x0505050505050505, 0xea };

  ak_uint8 iv[16] = { 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };


 /* создаем ключ */
  if( ak_bckey_create_kuznechik( &bkey ) != ak_error_ok ) return ak_libakrypt_destroy();
  if( ak_bckey_context_set_ptr( &bkey, testkey, sizeof( testkey ), ak_false ) != ak_error_ok ) return ak_libakrypt_destroy();

 /* запускаем тестовый пример */
  memset( c, 0, 9*8 );
  aead( &bkey, &bkey, iv, 16, a, 41, p, 67, c );


 return ak_libakrypt_destroy();
}


// char *str = NULL;
 struct bckey bkey;
// ak_uint64 y[2], gamma[2], delta[2], atemp[2], result[2] = { 0, 0 };



// memset( y, 0, 16 );


// /* последовательность для шифрования */
//  iv[15] &= 0x7f; // обнуляем старший бит
//  printf("     iv: %s\n\n", str = ak_ptr_to_hexstr( iv, 16, ak_true )); free( str );
//  bkey.encrypt( &bkey.key, iv, y );

//  for( int i = 0; i < 4; i++ ) {
//     printf("   y[%d]: %s\n", i+1, str = ak_ptr_to_hexstr( y, 16, ak_true )); free( str );
//     printf("                                      -^^-\n");

//     bkey.encrypt( &bkey.key, y, gamma );
//     printf("E(y[%d]): %s\n", i+1, str = ak_ptr_to_hexstr( gamma, 16, ak_true )); free( str );
//     printf("   p[%d]: %s\n", i+1, str = ak_ptr_to_hexstr( p+2*i, 16, ak_true )); free( str );

//     c[2*i] = p[2*i] ^= gamma[0];
//     c[2*i+1] = p[2*i+1] ^= gamma[1];
//     printf("   c[%d]: %s\n", i+1, str = ak_ptr_to_hexstr( c+2*i, 16, ak_true )); free( str );

//     y[0]++;
//     printf("\n");
//  }
//   /* теперь хвост */
//     printf("   y[5]: %s\n", str = ak_ptr_to_hexstr( y, 16, ak_true )); free( str );

//     bkey.encrypt( &bkey.key, y, gamma );
//     printf("E(y[5]): %s\n", str = ak_ptr_to_hexstr( gamma, 16, ak_true )); free( str );
//     gamma[0] = gamma[1]>>40;

//     printf("    msb: %s\n", str = ak_ptr_to_hexstr( gamma, 3, ak_true )); free( str );
//     printf("   p[5]: %s\n", str = ak_ptr_to_hexstr( p+8, 3, ak_true )); free( str );

//     c[8] = p[8]^gamma[0];
//     printf("   c[5]: %s\n", str = ak_ptr_to_hexstr( c+8, 3, ak_true )); free( str );



// printf("\nAuthentication:\n");

//  printf("  adata: %s\n\n", str = ak_ptr_to_hexstr( a, 41, ak_true )); free( str );


//  iv[15] ^= 0x80; // обнуляем старший бит
//  printf("     iv: %s\n\n", str = ak_ptr_to_hexstr( iv, 16, ak_true )); free( str );
//  bkey.encrypt( &bkey.key, iv, y );

//  for( int i = 0; i < 2; i++ ) {
//     printf("   z[%d]: %s\n", i+1, str = ak_ptr_to_hexstr( y, 16, ak_true )); free( str );
//     printf("                       -^-\n");

//     bkey.encrypt( &bkey.key, y, gamma );
//     printf("   h[%d]: %s = E(z[%d])\n", i+1, str = ak_ptr_to_hexstr( gamma, 16, ak_true ), i+1 ); free( str );
//     printf("   a[%d]: %s\n", i+1, str = ak_ptr_to_hexstr( a+2*i, 16, ak_true )); free( str );

//     ak_gf128_mul_pcmulqdq( delta, a+2*i, gamma );
//     printf("   d[%d]: %s = h[%d]*a[%d]\n\n", i+1, str = ak_ptr_to_hexstr( delta, 16, ak_true ), i+1, i+1); free( str );

//     y[1]++;
//     result[0] ^= delta[0];
//     result[1] ^= delta[1];
//  }

//     printf("   z[3]: %s\n", str = ak_ptr_to_hexstr( y, 16, ak_true )); free( str );
//     printf("                       -^-\n");

//     bkey.encrypt( &bkey.key, y, gamma );
//     printf("   h[3]: %s = E(z[3])\n", str = ak_ptr_to_hexstr( gamma, 16, ak_true )); free( str );

//     atemp[1] = ( a[5] << 56 ) ^ ( a[4] >> 8 );
//     atemp[0] = ( a[4] << 56 );
//     printf("  a'[3]: %s\n", str = ak_ptr_to_hexstr( atemp, 16, ak_true )); free( str );

//     ak_gf128_mul_pcmulqdq( delta, atemp, gamma );
//     printf("   d[3]: %s = h[3]*a'[3]\n\n", str = ak_ptr_to_hexstr( delta, 16, ak_true )); free( str );

//     y[1]++;
//     result[0] ^= delta[0];
//     result[1] ^= delta[1];


//    //теперь цикл для c



//     printf("    sum: %s\n\n", str = ak_ptr_to_hexstr( result, 16, ak_true )); free( str );

