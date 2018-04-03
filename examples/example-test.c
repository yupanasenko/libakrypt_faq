 #include <stdio.h>
 #
 #include <ak_aead.h>


/* ----------------------------------------------------------------------------------------------- */
 void multiplication_test()
{
 int i = 0;
 char out[128];
 ak_uint64 x, y, z;
 ak_uint128 a, b, c;

 /* тестовые значения для умножения 128 битных векторов */
 a.q[0] = 0x63746f725d53475dLL; a.q[1] = 0x7b5b546573745665LL;
 b.q[0] = 0x5b477565726f6e5dLL; b.q[1] = 0x4869285368617929LL;

 for( i = 0; i < 10; i++ ) {
    ak_ptr_to_hexstr_static( &a, 16, out, 128, ak_true ); printf("  a = %s\n", out );
    ak_ptr_to_hexstr_static( &b, 16, out, 128, ak_true ); printf("  b = %s\n", out );

    ak_gf128_mul( &c, &a, &b );
    ak_ptr_to_hexstr_static( &c, 16, out, 128, ak_true ); printf("a*b = %s\n\n", out );
    a.q[0] = b.q[0]; a.q[1] = b.q[1];
    b.q[0] = c.q[0]; b.q[1] = c.q[1];
 }

 x = c.q[0]; y = c.q[1];
 for( i = 0; i < 10; i++ ) {
    ak_ptr_to_hexstr_static( &x, 8, out, 128, ak_true ); printf("  x = %s\n", out );
    ak_ptr_to_hexstr_static( &y, 8, out, 128, ak_true ); printf("  y = %s\n", out );

    ak_gf64_mul( &z, &x, &y );
    ak_ptr_to_hexstr_static( &z, 8, out, 128, ak_true ); printf("x*y = %s\n\n", out );
    x = y; y = z;
 }
}

/* ----------------------------------------------------------------------------------------------- */
 void aead( ak_bckey keyEncryption, ak_bckey keyAuthentication, ak_pointer iv, size_t iv_size,
        ak_pointer adata, size_t adata_size, ak_pointer pdata, size_t pdata_size,
        ak_pointer cdata, ak_pointer icode )
{
 memset( cdata, 0, pdata_size );
 memset( icode, 0, keyEncryption->ivector.size );

 size_t i = 0, j = 0;
 char *str = NULL;

 size_t bsize = keyEncryption->ivector.size,
        blocks = pdata_size / bsize,
        tail = pdata_size - blocks*bsize;

 size_t absize = keyAuthentication->ivector.size,
        ablocks = adata_size / absize,
        atail = adata_size - ablocks*absize;

 printf("aead started:\n plain blocks: %zu, plain tail: %zu bytes\n", blocks, tail );
 printf(" advanced data blocks: %zu, advanced data tail: %zu bytes\n", ablocks, atail );

  ak_uint8 ivector[16], z[16], h[16], y[16], temp[16], mulres[16], e[16], sum[16];
  memset( sum, 0, 16 );

  ak_uint8 *a = (ak_uint8 *) adata;
  ak_uint8 *p = (ak_uint8 *) pdata;
  ak_uint8 *c = (ak_uint8 *) cdata;

 /* Начальные значения счетчиков */
  memset( ivector, 0, 16 );
  memcpy( ivector, iv, absize ); /* копируем нужное количество байт */
  ivector[absize-1] = ( ivector[absize-1]&0x7F ) ^ 0x80; // принудительно устанавливаем старший бит в 1

  printf("\nFirst phase (additional data hashing with authentication key)\n");
  printf("     iv: %s (with most significant bit is equal to 1)\n\n", str = ak_ptr_to_hexstr( ivector, absize, ak_true )); free( str );
  keyAuthentication->encrypt( &keyAuthentication->key, ivector, z );

  for( i = 0; i < ablocks; i++ ) {
     printf("   z[%lu]: %s\n", i+1, str = ak_ptr_to_hexstr( z, absize, ak_true )); free( str );
     printf("       "); for( j = 0; j < absize; j++ ) printf(" ");
     printf("-^-\n");

     keyAuthentication->encrypt( &keyAuthentication->key, z, h );
     printf("   h[%lu]: %s\n", i+1, str = ak_ptr_to_hexstr( h, absize, ak_true )); free( str );
     printf("   a[%lu]: %s\n", i+1, str = ak_ptr_to_hexstr( a+absize*i, absize, ak_true )); free( str );

     if( keyAuthentication->ivector.size == 16 ) ak_gf128_mul( mulres, h, a+absize*i );
       else ak_gf64_mul( mulres, h, a+absize*i );
     printf(" h*a[%lu]: %s\n", i+1, str = ak_ptr_to_hexstr( mulres, absize, ak_true )); free( str );

     for( j = 0; j < 16; j++ ) sum[j] ^= mulres[j];
     printf(" sum[%lu]: %s\n", i+1, str = ak_ptr_to_hexstr( sum, absize, ak_true )); free( str );

     ((ak_uint32 *)(z+(absize/2)))[0]++;  /* !!!!!!!!!! */
     printf("\n");
  }

 /* обрабатываем хвост */
  if( atail ) {
     printf("   z[%zu]: %s\n", ablocks+1, str = ak_ptr_to_hexstr( z, absize, ak_true )); free( str );
     printf("       "); for( j = 0; j < absize; j++ ) printf(" ");
     printf("-^-\n");

     keyAuthentication->encrypt( &keyAuthentication->key, z, h );
     printf("   h[%zu]: %s\n", ablocks+1, str = ak_ptr_to_hexstr( h, absize, ak_true )); free( str );

     memset( temp, 0, 16 );
     memcpy( temp+absize-atail, a+absize*ablocks, atail );
     printf("   a[%zu]: %s\n", ablocks+1, str = ak_ptr_to_hexstr( temp, absize, ak_true )); free( str );

     if( keyAuthentication->ivector.size == 16 ) ak_gf128_mul( mulres, h, temp );
       else ak_gf64_mul( mulres, h, temp );

     printf(" h*a[%zu]: %s\n", ablocks+1, str = ak_ptr_to_hexstr( mulres, absize, ak_true )); free( str );

     for( j = 0; j < 16; j++ ) sum[j] ^= mulres[j];
     printf(" sum[%zu]: %s\n", ablocks+1, str = ak_ptr_to_hexstr( sum, absize, ak_true )); free( str );

     ((ak_uint32 *)(z+(absize/2)))[0]++;
     printf("\n");
  }

 /* далее вторая часть */
  printf("Second phase (encryption plain text with encryption key and hashing cipher text with authentication key)\n");
  memset( ivector, 0, 16 );
  memcpy( ivector, iv, bsize ); /* копируем нужное количество байт */
  ivector[bsize-1] = ( ivector[bsize-1]&0x7F ); // принудительно устанавливаем старший бит в 0

  printf("     iv: %s\n\n", str = ak_ptr_to_hexstr( ivector, bsize, ak_true )); free( str );
  keyEncryption->encrypt( &keyEncryption->key, ivector, y );

  for( i = 0; i < blocks; i++ ) {
     printf("   z[%zu]: %s\n", i+ablocks+2, str = ak_ptr_to_hexstr( z, absize, ak_true )); free( str );
     printf("       "); for( j = 0; j < absize; j++ ) printf(" ");
     printf("-^-\n");

     keyAuthentication->encrypt( &keyAuthentication->key, z, h );
     printf("   h[%zu]: %s\n", i+ablocks+2, str = ak_ptr_to_hexstr( h, absize, ak_true )); free( str );

     printf("   y[%zu]: %s\n", i+1, str = ak_ptr_to_hexstr( y, bsize, ak_true )); free( str );
     printf("       "); for( j = 0; j < 2*bsize; j++ ) printf(" ");
     printf("-^-\n");

     keyEncryption->encrypt( &keyEncryption->key, y, e );
     printf("   e[%zu]: %s = E(y[%zu])\n", i+1, str = ak_ptr_to_hexstr( e, bsize, ak_true ), i+1 ); free( str );
     printf("   p[%zu]: %s\n", i+1, str = ak_ptr_to_hexstr( p+i*bsize, bsize, ak_true )); free( str );

     for( j = 0; j < 16; j++ ) c[j+i*bsize] = p[j+i*bsize]^e[j];
     printf("   c[%zu]: %s\n", i+1, str = ak_ptr_to_hexstr( c+i*bsize, bsize, ak_true )); free( str );

     /* теперь умножение */
     if( keyAuthentication->ivector.size == 16 ) ak_gf128_mul( mulres, h, c+i*bsize );
       else ak_gf64_mul( mulres, h, c+i*bsize );

     printf("       : %s <- h[%zu]*c[%zu]\n",
                   str = ak_ptr_to_hexstr( mulres, absize, ak_true ), i+ablocks+2, i+1 ); free( str );

     for( j = 0; j < 16; j++ ) sum[j] ^= mulres[j];
     printf(" sum[%lu]: %s\n", i+ablocks+2, str = ak_ptr_to_hexstr( sum, absize, ak_true )); free( str );

     ((ak_uint32 *)(z+(absize/2)))[0]++;
     ((ak_uint32 *)y)[0]++;
     printf("\n");
  }

  if( tail ) {
     printf("   z[%zu]: %s\n", ablocks+blocks+2, str = ak_ptr_to_hexstr( z, absize, ak_true )); free( str );
     printf("       "); for( j = 0; j < absize; j++ ) printf(" ");
     printf("-^-\n");

     keyAuthentication->encrypt( &keyAuthentication->key, z, h );
     printf("   h[%zu]: %s\n", ablocks+blocks+2, str = ak_ptr_to_hexstr( h, absize, ak_true )); free( str );

     printf("   y[%zu]: %s\n", blocks+1, str = ak_ptr_to_hexstr( y, bsize, ak_true )); free( str );
     printf("       "); for( j = 0; j < 2*bsize; j++ ) printf(" ");
     printf("-^-\n");

     keyEncryption->encrypt( &keyEncryption->key, y, e );
     printf("   e[%zu]: %s = E(y[%zu])\n", blocks+1, str = ak_ptr_to_hexstr( e, bsize, ak_true ), i+1 ); free( str );
     printf("   p[%zu]: %s\n", blocks+1, str = ak_ptr_to_hexstr( p+blocks*bsize, tail, ak_true )); free( str );

     for( j = 0; j < tail; j++ ) { c[bsize*blocks+j] = p[ blocks*bsize+j ] ^ e[bsize-tail+j]; }
     printf("   c[%zu]: %s (xor with most significant bytes)\n",
                                 blocks+1, str = ak_ptr_to_hexstr( c+blocks*bsize, tail, ak_true )); free( str );

     memset( temp, 0, 16 );
     memcpy( temp+(bsize-tail), c+bsize*blocks, tail );
     printf("   c[%zu]: %s (vector for multiplication)\n",
                                 blocks+1, str = ak_ptr_to_hexstr( temp, bsize, ak_true )); free( str );
     /* теперь умножение */
     if( keyAuthentication->ivector.size == 16 ) ak_gf128_mul( mulres, h, temp );
       else ak_gf64_mul( mulres, h, temp );

     printf("       : %s <- h[%zu]*c[%zu]\n",
                   str = ak_ptr_to_hexstr( mulres, absize, ak_true ), blocks+ablocks+2, blocks+1 ); free( str );

     for( j = 0; j < 16; j++ ) sum[j] ^= mulres[j];
     printf(" sum[%zu]: %s\n", blocks+ablocks+2, str = ak_ptr_to_hexstr( sum, absize, ak_true )); free( str );

     ((ak_uint32 *)(z+(absize/2)))[0]++;
     ((ak_uint32 *)y)[0]++;
     printf("\n");
  }


  printf("Finalize\n");

 /* теперь длины и шифрование */
     printf("   z[%zu]: %s\n", ablocks+blocks+3, str = ak_ptr_to_hexstr( z, absize, ak_true )); free( str );
     printf("       "); for( j = 0; j < absize; j++ ) printf(" ");
     printf("-^-\n");

     keyAuthentication->encrypt( &keyAuthentication->key, z, h );
     printf("   h[%zu]: %s\n", ablocks+blocks+3, str = ak_ptr_to_hexstr( h, absize, ak_true )); free( str );

     memset( temp, 0, 16 );
     ((ak_uint32*)temp)[0] = pdata_size*8;
     ((ak_uint32 *)(temp+absize/2))[0] = adata_size*8;
     printf("    len: %s\n", str = ak_ptr_to_hexstr( temp, absize, ak_true )); free( str );

     /* теперь умножение */
     if( keyAuthentication->ivector.size == 16 ) ak_gf128_mul( mulres, h, temp );
       else ak_gf64_mul( mulres, h, temp );

     printf("       : %s <- h[%zu]*len\n",
       str = ak_ptr_to_hexstr( mulres, absize, ak_true ), ablocks+blocks+3 ); free( str );

     for( j = 0; j < 16; j++ ) sum[j] ^= mulres[j];
     printf(" sum[%zu]: %s\n", blocks+ablocks+3, str = ak_ptr_to_hexstr( sum, absize, ak_true )); free( str );

     keyAuthentication->encrypt( &keyAuthentication->key, sum, icode );
     printf("  icode: %s (E(sum) with authentication key)\n",
                                               str = ak_ptr_to_hexstr( icode, absize, ak_true )); free( str );
}

/* ----------------------------------------------------------------------------------------------- */
 #include <time.h>
 int main( void )
{
 char *out;
 ak_libakrypt_create( ak_function_log_stderr );

 /* тест на умножение */
  multiplication_test();

 ak_uint8 testkey_block128[32] = {
     0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
     0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

 ak_uint8 testkey_block64[32] = {
     0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

 /* открытый текст из ГОСТ Р 34.13-2015, приложение А.1, подлежащий зашифрованию */
 ak_uint64 plain[9] = {
    0xffeeddccbbaa9988, 0x1122334455667700, 0x8899aabbcceeff0a, 0x0011223344556677,
    0x99aabbcceeff0a00, 0x1122334455667788, 0xaabbcceeff0a0011, 0x2233445566778899, 0xaabbcc };

  ak_uint8 cipher[72], icode[16];

 /* асссоциированные данные */
  ak_uint64 a[6] = {
    0x0101010101010101, 0x0202020202020202, 0x0303030303030303, 0x0404040404040404,
    0x0505050505050505, 0xea };

  ak_uint8 iv128[16] = { 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
  ak_uint8 iv64[8] = { 0x59, 0x0a, 0x13, 0x3c, 0x6b, 0xf0, 0xde, 0x92 };

 size_t plain_len = 67, associated_len = 41;
 ak_bckey encryptionKey, authenticationKey;

 printf("plain data len: %zu nytes, %zu bits (in hexademal %zx bits)\n", plain_len, plain_len << 3, plain_len << 3 );
 printf("plain data: %s\n", out = ak_ptr_to_hexstr( plain, plain_len, ak_true )); free( out );
 printf("plaint data (blocks on 16 byte):\n");
 for( int i = 0; i < 4; i++ ) {
    printf( "p[%d] = %s\n", i+1, out = ak_ptr_to_hexstr((ak_uint8 *)plain+16*i, 16, ak_true )); free( out );
 }
 printf( "p[5] = %s\n", out = ak_ptr_to_hexstr((ak_uint8 *)plain+64, 3, ak_true )); free( out );

 printf("plaint data (blocks on 8 byte):\n");
 for( int i = 0; i < 8; i++ ) {
    printf( "p[%d] = %s\n", i+1, out = ak_ptr_to_hexstr((ak_uint8 *)plain+8*i, 8, ak_true )); free( out );
 }
 printf( "p[9] = %s\n\n", out = ak_ptr_to_hexstr((ak_uint8 *)plain+64, 3, ak_true )); free( out );

 printf("associated data len: %zu nytes, %zu bits (in hexademal %zx bits)\n", associated_len, associated_len << 3, associated_len << 3 );
 printf("associated data: %s\n", out = ak_ptr_to_hexstr( a, associated_len, ak_true )); free( out );
 printf("associated data (blocks on 16 byte):\n");
 for( int i = 0; i < 2; i++ ) {
    printf( "a[%d] = %s\n", i+1, out = ak_ptr_to_hexstr((ak_uint8 *)a+16*i, 16, ak_true )); free( out );
 }
 printf( "a[3] = %s\n", out = ak_ptr_to_hexstr((ak_uint8 *)a+32, 9, ak_true )); free( out );

 printf("associated data (blocks on 8 byte):\n");
 for( int i = 0; i < 5; i++ ) {
    printf( "a[%d] = %s\n", i+1, out = ak_ptr_to_hexstr((ak_uint8 *)a+8*i, 8, ak_true )); free( out );
 }
 printf( "p[6] = %s\n\n", out = ak_ptr_to_hexstr((ak_uint8 *)a+40, 1, ak_true )); free( out );


 /* пример первый: один ключ + 128 бит блок ------------------------------------------------- */
 printf("\n\nEXAMPLE N1 (kuznechik with one key): \n");

  if( ak_bckey_create_kuznechik( encryptionKey = (ak_bckey) malloc( sizeof( struct bckey ))) != ak_error_ok )
    return ak_libakrypt_destroy();
  if( ak_bckey_context_set_ptr( encryptionKey, testkey_block128, 32, ak_true ) != ak_error_ok )
    return ak_libakrypt_destroy();

  if( ak_bckey_create_kuznechik( authenticationKey = (ak_bckey) malloc( sizeof( struct bckey ))) != ak_error_ok )
    return ak_libakrypt_destroy();
  if( ak_bckey_context_set_ptr( authenticationKey, testkey_block128, 32, ak_true ) != ak_error_ok )
    return ak_libakrypt_destroy();

 printf("encryption key:     %s (GOST R 34.13-2015, App. A)\n",
                               out = ak_ptr_to_hexstr(  testkey_block128, 32, ak_true )); free( out );
 printf("authentication key: %s (GOST R 34.13-2015, App. A)\n\n",
                                out = ak_ptr_to_hexstr(  testkey_block128, 32, ak_true )); free( out );
 printf("iv: %s\n", out = ak_ptr_to_hexstr( iv128, 16, ak_true )); free( out );

 aead( encryptionKey, authenticationKey, iv128, 16, a, associated_len, plain, plain_len, cipher, icode );

 printf("\nalgorithm summary:\n");
 printf("icode: %s\n", out = ak_ptr_to_hexstr( icode, encryptionKey->ivector.size, ak_true )); free( out );
 printf("encrypted: %s\n", out = ak_ptr_to_hexstr( cipher, plain_len, ak_true )); free( out );

 encryptionKey = ak_bckey_delete( encryptionKey );
 authenticationKey = ak_bckey_delete( authenticationKey );

 /* пример второй: два ключа + 128 бит блок ------------------------------------------------- */
 printf("\n\nEXAMPLE N2 (kuznechik wit two keys): \n");

  if( ak_bckey_create_kuznechik( encryptionKey = (ak_bckey) malloc( sizeof( struct bckey ))) != ak_error_ok )
    return ak_libakrypt_destroy();
  if( ak_bckey_context_set_ptr( encryptionKey, testkey_block128, 32, ak_true ) != ak_error_ok )
    return ak_libakrypt_destroy();

  if( ak_bckey_create_kuznechik( authenticationKey = (ak_bckey) malloc( sizeof( struct bckey ))) != ak_error_ok )
    return ak_libakrypt_destroy();
  if( ak_bckey_context_set_ptr( authenticationKey, testkey_block64, 32, ak_true ) != ak_error_ok )
    return ak_libakrypt_destroy();

 printf("encryption key:     %s (GOST R 34.13-2015, App. A)\n",
                               out = ak_ptr_to_hexstr(  testkey_block128, 32, ak_true )); free( out );
 printf("authentication key: %s (GOST R 34.13-2015, App. B)\n\n",
                                out = ak_ptr_to_hexstr(  testkey_block64, 32, ak_true )); free( out );
 printf("iv: %s\n", out = ak_ptr_to_hexstr( iv128, 16, ak_true )); free( out );

 aead( encryptionKey, authenticationKey, iv128, 16, a, associated_len, plain, plain_len, cipher, icode );

 printf("\nalgorithm summary:\n");
 printf("icode: %s\n", out = ak_ptr_to_hexstr( icode, encryptionKey->ivector.size, ak_true )); free( out );
 printf("encrypted: %s\n", out = ak_ptr_to_hexstr( cipher, plain_len, ak_true )); free( out );

 encryptionKey = ak_bckey_delete( encryptionKey );
 authenticationKey = ak_bckey_delete( authenticationKey );


 /* пример третий: один ключ + 64 бит блок ------------------------------------------------- */
 printf("\n\nEXAMPLE N3 (magma with one key): \n");

  if( ak_bckey_create_magma( encryptionKey = (ak_bckey) malloc( sizeof( struct bckey ))) != ak_error_ok )
    return ak_libakrypt_destroy();
  if( ak_bckey_context_set_ptr( encryptionKey, testkey_block64, 32, ak_true ) != ak_error_ok )
    return ak_libakrypt_destroy();

  if( ak_bckey_create_magma( authenticationKey = (ak_bckey) malloc( sizeof( struct bckey ))) != ak_error_ok )
    return ak_libakrypt_destroy();
  if( ak_bckey_context_set_ptr( authenticationKey, testkey_block64, 32, ak_true ) != ak_error_ok )
    return ak_libakrypt_destroy();

 printf("encryption key:     %s (GOST R 34.13-2015, App. B)\n",
                               out = ak_ptr_to_hexstr(  testkey_block64, 32, ak_true )); free( out );
 printf("authentication key: %s (GOST R 34.13-2015, App. B)\n\n",
                                out = ak_ptr_to_hexstr(  testkey_block64, 32, ak_true )); free( out );
 printf("iv: %s\n", out = ak_ptr_to_hexstr( iv64, 8, ak_true )); free( out );

 aead( encryptionKey, authenticationKey, iv64, 8, a, associated_len, plain, plain_len, cipher, icode );

 printf("\nalgorithm summary:\n");
 printf("icode: %s\n", out = ak_ptr_to_hexstr( icode, encryptionKey->ivector.size, ak_true )); free( out );
 printf("encrypted: %s\n", out = ak_ptr_to_hexstr( cipher, plain_len, ak_true )); free( out );

 encryptionKey = ak_bckey_delete( encryptionKey );
 authenticationKey = ak_bckey_delete( authenticationKey );


 /* пример четвертый: два ключа + 64 бит блок ------------------------------------------------- */
 printf("\n\nEXAMPLE N4 (magma with two keys): \n");

  if( ak_bckey_create_magma( encryptionKey = (ak_bckey) malloc( sizeof( struct bckey ))) != ak_error_ok )
    return ak_libakrypt_destroy();
  if( ak_bckey_context_set_ptr( encryptionKey, testkey_block64, 32, ak_true ) != ak_error_ok )
    return ak_libakrypt_destroy();

  if( ak_bckey_create_magma( authenticationKey = (ak_bckey) malloc( sizeof( struct bckey ))) != ak_error_ok )
    return ak_libakrypt_destroy();
  if( ak_bckey_context_set_ptr( authenticationKey, testkey_block128, 32, ak_true ) != ak_error_ok )
    return ak_libakrypt_destroy();

 printf("encryption key:     %s (GOST R 34.13-2015, App. B)\n",
                               out = ak_ptr_to_hexstr(  testkey_block64, 32, ak_true )); free( out );
 printf("authentication key: %s (GOST R 34.13-2015, App. A)\n\n",
                                out = ak_ptr_to_hexstr(  testkey_block128, 32, ak_true )); free( out );
 printf("iv: %s\n", out = ak_ptr_to_hexstr( iv64, 8, ak_true )); free( out );

 aead( encryptionKey, authenticationKey, iv64, 8, a, associated_len, plain, plain_len, cipher, icode );

 printf("\nalgorithm summary:\n");
 printf("icode: %s\n", out = ak_ptr_to_hexstr( icode, encryptionKey->ivector.size, ak_true )); free( out );
 printf("encrypted: %s\n", out = ak_ptr_to_hexstr( cipher, plain_len, ak_true )); free( out );

 encryptionKey = ak_bckey_delete( encryptionKey );
 authenticationKey = ak_bckey_delete( authenticationKey );

 return ak_libakrypt_destroy();
}
