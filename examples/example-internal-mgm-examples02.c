 #include <stdio.h>
 #include <ak_aead.h>

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
  int i = 0;
  ak_uint8 testkey_block128[32] = {
     0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
     0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

  ak_uint64 counter = 0xAE42EB0700000000LL;
  ak_uint32 bytelen = 0, number = 200;

  ak_uint8 adata[16], iv[16], edata[1600], out[1600], string[4096], imito[16];
  struct bckey bkey, akey;

  ak_libakrypt_create( ak_function_log_stderr );

 printf("вывод массивов от младших (слева) к старшим (справа)\n\n");

 /* делаем данные для шифрования */
  for( i = 0; i < sizeof( edata ); i++ ) edata[i] = (1 + i + i*i );
  ak_ptr_to_hexstr_static( edata, sizeof( edata ), string, sizeof( string ), ak_false );
  printf("initial data: %s\n\n", string );

  ak_ptr_to_hexstr_static( testkey_block128, 32, string, sizeof( string ), ak_false );
  printf("encryption & authentication key: %s\n\n", string );

 /*  инициируем ключ */
  ak_bckey_create_kuznechik( &bkey );
  ak_bckey_context_set_ptr( &bkey, testkey_block128, 32, ak_true );
  ak_bckey_create_kuznechik( &akey );
  ak_bckey_context_set_ptr( &akey, testkey_block128, 32, ak_true );


  for( bytelen = 49; bytelen <= 1600; bytelen++ ) {
     counter++; number++; if( number > 1024 ) number = 0;
     printf("counter: %llu (%016llX in hex) (как целые числа)\n", counter, counter );
     printf("N: %u (%04X in hex) (как целые числа)\n", number, number );
     printf("length of encrypted data: %d octets (%04X in hex)\n", bytelen, bytelen );

     /* формируем associated data */
     memcpy( adata, &counter, 8 );
     memcpy( adata+8, &number, 2 );
     memcpy( adata+10, &bytelen, 2 ); //заняли 12 младших байт
     memset( iv, 0, 16 );
     memcpy( iv+4, adata, 8 ); // сделали iv

     ak_ptr_to_hexstr_static( adata, 12, string, sizeof( string ), ak_false );
     printf("ad: %s\n", string );
     ak_ptr_to_hexstr_static( edata, bytelen, string, sizeof( string ), ak_false );
     printf("ae: %s\n", string );
     ak_ptr_to_hexstr_static( iv, 16, string, sizeof( string ), ak_false );
     printf("iv: %s\n", string );

     memset( imito, 0, 16 );
     ak_bckey_context_encrypt_mgm( &bkey, &akey, adata, 12, edata, out, bytelen, iv, sizeof( iv ),
                                                                              imito, sizeof( imito ));
     ak_ptr_to_hexstr_static( out, bytelen, string, sizeof( string ), ak_false );
     printf("en: %s (encrypted text)\n", string );
     ak_ptr_to_hexstr_static( imito, sizeof( imito ), string, sizeof( string ), ak_false );
     printf("im: %s (imito)\n", string );
     ak_ptr_to_hexstr_static( imito, sizeof( imito ), string, sizeof( string ), ak_true );
     printf("im: %s (imito in GOST style, reverse!)\n", string );
     printf("\n");
  }

return ak_libakrypt_destroy();
}
