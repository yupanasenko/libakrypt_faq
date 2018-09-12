 #include <stdio.h>
 #include <ak_aead.h>

/* ----------------------------------------------------------------------------------------------- */
 #include <time.h>
 int main( void )
{
 char *out = NULL;
 ak_buffer result = NULL;

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

  ak_uint8 cipher[72];

 /* асссоциированные данные */
  ak_uint64 a[6] = {
    0x0101010101010101, 0x0202020202020202, 0x0303030303030303, 0x0404040404040404,
    0x0505050505050505, 0xea };

  ak_uint8 iv128[16] = { 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
  ak_uint8 iv64[8] = { 0x59, 0x0a, 0x13, 0x3c, 0x6b, 0xf0, 0xde, 0x92 };

  size_t plain_len = 67, associated_len = 41;
  struct bckey mkeyA, mkeyB, kkeyA, kkeyB; /* все комбинации ключей */


  struct mgm_ctx mgm;
  memset( &mgm, 0, sizeof( struct mgm_ctx ));

  ak_libakrypt_create( ak_function_log_stderr );

 /* инициализируем ключи */
  ak_bckey_create_magma( &mkeyA ); ak_bckey_context_set_ptr( &mkeyA, testkey_block128, 32, ak_true );
  ak_bckey_create_magma( &mkeyB ); ak_bckey_context_set_ptr( &mkeyB, testkey_block64, 32, ak_true );
  ak_bckey_create_kuznechik( &kkeyA ); ak_bckey_context_set_ptr( &kkeyA, testkey_block128, 32, ak_true );
  ak_bckey_create_kuznechik( &kkeyB ); ak_bckey_context_set_ptr( &kkeyB, testkey_block64, 32, ak_true );

 /* тест номер один */
  memset( cipher, 0, plain_len );
  printf(" mgm example one for Kuznechik ");
  result = ak_bckey_context_encrypt_mgm( &kkeyA, &kkeyA, a, associated_len,
                                                 plain, cipher, plain_len, iv128, sizeof(iv128), NULL, 16 );
  if( ak_error_get_value( ) != ak_error_ok ) printf("is Wrong\n");
    else printf("is Ok\n");

  printf(" cipher text: %s ", out = ak_ptr_to_hexstr( cipher, plain_len, ak_true )); free( out );
  if( result ) {
    printf("(icode: %s)\n\n", out = ak_buffer_to_hexstr( result, ak_true )); free( out );
    result = ak_buffer_delete( result );
  } else printf(" (mgm icode undefined)\n\n");

 /* тест номер два */
  memset( cipher, 0, plain_len );
  printf(" mgm example two for Kuznechik ");
  result = ak_bckey_context_encrypt_mgm( &kkeyA, &kkeyB, a, associated_len,
                                                 plain, cipher, plain_len, iv128, sizeof(iv128), NULL, 16 );
  if( ak_error_get_value( ) != ak_error_ok ) printf("is Wrong\n");
    else printf("is Ok\n");

  printf(" cipher text: %s ", out = ak_ptr_to_hexstr( cipher, plain_len, ak_true )); free( out );
  if( result ) {
    printf("(icode: %s)\n\n", out = ak_buffer_to_hexstr( result, ak_true )); free( out );
    result = ak_buffer_delete( result );
  } else printf(" (mgm icode undefined)\n\n");

 /* тест номер три */
  memset( cipher, 0, plain_len );
  printf(" mgm example three for Magma ");
  result = ak_bckey_context_encrypt_mgm( &mkeyB, &mkeyB, a, associated_len,
                                                 plain, cipher, plain_len, iv64, sizeof(iv64), NULL, 8 );
  if( ak_error_get_value( ) != ak_error_ok ) printf("is Wrong\n");
    else printf("is Ok\n");

  printf(" cipher text: %s ", out = ak_ptr_to_hexstr( cipher, plain_len, ak_true )); free( out );
  if( result ) {
    printf("(icode: %s)\n\n", out = ak_buffer_to_hexstr( result, ak_true )); free( out );
    result = ak_buffer_delete( result );
  } else printf(" (mgm icode undefined)\n\n");

 /* тест номер четыре */
  memset( cipher, 0, plain_len );
  printf(" mgm example four for Magma ");
  result = ak_bckey_context_encrypt_mgm( &mkeyB, &mkeyA, a, associated_len,
                                                 plain, cipher, plain_len, iv64, sizeof(iv64), NULL, 8 );
  if( ak_error_get_value( ) != ak_error_ok ) printf("is Wrong\n");
    else printf("is Ok\n");

  printf(" cipher text: %s ", out = ak_ptr_to_hexstr( cipher, plain_len, ak_true )); free( out );
  if( result ) {
    printf("(icode: %s)\n\n", out = ak_buffer_to_hexstr( result, ak_true )); free( out );
    result = ak_buffer_delete( result );
  } else printf(" (mgm icode undefined)\n\n");

 /* тест номер пять */
  memset( cipher, 0, plain_len );
  printf(" mgm example five for Kuznechik (key form Annex.A, encryption only) ");
  result = ak_bckey_context_encrypt_mgm( &kkeyA, NULL, NULL, 0,
                                               plain, cipher, plain_len, iv128, sizeof(iv128), NULL, 16 );
  if( ak_error_get_value( ) != ak_error_ok ) printf("is Wrong\n");
    else printf("is Ok\n");

  printf(" cipher text: %s ", out = ak_ptr_to_hexstr( cipher, plain_len, ak_true )); free( out );
  if( result ) {
    printf("(icode: %s)\n\n", out = ak_buffer_to_hexstr( result, ak_true )); free( out );
    result = ak_buffer_delete( result );
  } else printf(" (mgm icode undefined)\n\n");

 /* тест номер шесть */
  memset( cipher, 0, plain_len );
  printf(" mgm example six for Kuznechik (key form Annex. B, encryption only) ");
  result = ak_bckey_context_encrypt_mgm( &kkeyB, NULL, NULL, 0,
                                               plain, cipher, plain_len, iv128, sizeof(iv128), NULL, 16 );
  if( ak_error_get_value( ) != ak_error_ok ) printf("is Wrong\n");
    else printf("is Ok\n");

  printf(" cipher text: %s ", out = ak_ptr_to_hexstr( cipher, plain_len, ak_true )); free( out );
  if( result ) {
    printf("(icode: %s)\n\n", out = ak_buffer_to_hexstr( result, ak_true )); free( out );
    result = ak_buffer_delete( result );
  } else printf(" (mgm icode undefined)\n\n");

 /* тест номер семь */
  memset( cipher, 0, plain_len );
  printf(" mgm example seven for Magma (key form Annex.A, encryption only) ");
  result = ak_bckey_context_encrypt_mgm( &mkeyA, NULL, NULL, 0,
                                               plain, cipher, plain_len, iv64, sizeof(iv64), NULL, 8 );
  if( ak_error_get_value( ) != ak_error_ok ) printf("is Wrong\n");
    else printf("is Ok\n");

  printf(" cipher text: %s ", out = ak_ptr_to_hexstr( cipher, plain_len, ak_true )); free( out );
  if( result ) {
    printf("(icode: %s)\n\n", out = ak_buffer_to_hexstr( result, ak_true )); free( out );
    result = ak_buffer_delete( result );
  } else printf(" (mgm icode undefined)\n\n");

 /* тест номер восемь */
  memset( cipher, 0, plain_len );
  printf(" mgm example eight for Magma (key form Annex.B, encryption only) ");
  result = ak_bckey_context_encrypt_mgm( &mkeyB, NULL, NULL, 0,
                                               plain, cipher, plain_len, iv64, sizeof(iv64), NULL, 8 );
  if( ak_error_get_value( ) != ak_error_ok ) printf("is Wrong\n");
    else printf("is Ok\n");

  printf(" cipher text: %s ", out = ak_ptr_to_hexstr( cipher, plain_len, ak_true )); free( out );
  if( result ) {
    printf("(icode: %s)\n\n", out = ak_buffer_to_hexstr( result, ak_true )); free( out );
    result = ak_buffer_delete( result );
  } else printf(" (mgm icode undefined)\n\n");

 /* тест номер nine */
  memset( cipher, 0, plain_len );
  printf(" mgm example nine for Kuznechik (key form Annex.A, integrity only) ");
  result = ak_bckey_context_encrypt_mgm( NULL, &kkeyA, a, associated_len,
                                                     NULL, NULL, 0, iv128, sizeof(iv128), NULL, 16 );
  if( ak_error_get_value( ) != ak_error_ok ) printf("is Wrong\n");
    else printf("is Ok\n");

  /* printf(" cipher text: %s ", out = ak_ptr_to_hexstr( cipher, plain_len, ak_true )); free( out ); */
  if( result ) {
    printf("(icode: %s)\n\n", out = ak_buffer_to_hexstr( result, ak_true )); free( out );
    result = ak_buffer_delete( result );
  } else printf(" (mgm icode undefined)\n\n");

 /* тест номер ten */
  memset( cipher, 0, plain_len );
  printf(" mgm example ten for Kuznechik (key form Annex.B, integrity only) ");
  result = ak_bckey_context_encrypt_mgm( NULL, &kkeyB, a, associated_len,
                                                     NULL, NULL, 0, iv128, sizeof(iv128), NULL, 16 );
  if( ak_error_get_value( ) != ak_error_ok ) printf("is Wrong\n");
    else printf("is Ok\n");

  /* printf(" cipher text: %s ", out = ak_ptr_to_hexstr( cipher, plain_len, ak_true )); free( out ); */
  if( result ) {
    printf("(icode: %s)\n\n", out = ak_buffer_to_hexstr( result, ak_true )); free( out );
    result = ak_buffer_delete( result );
  } else printf(" (mgm icode undefined)\n\n");


 /* тест номер eleven */
  memset( cipher, 0, plain_len );
  printf(" mgm example eleven for Magma (key form Annex.A, integrity only) ");
  result = ak_bckey_context_encrypt_mgm( NULL, &mkeyA, a, associated_len,
                                                     NULL, NULL, 0, iv64, sizeof(iv64), NULL, 8 );
  if( ak_error_get_value( ) != ak_error_ok ) printf("is Wrong\n");
    else printf("is Ok\n");

  /* printf(" cipher text: %s ", out = ak_ptr_to_hexstr( cipher, plain_len, ak_true )); free( out ); */
  if( result ) {
    printf("(icode: %s)\n\n", out = ak_buffer_to_hexstr( result, ak_true )); free( out );
    result = ak_buffer_delete( result );
  } else printf(" (mgm icode undefined)\n\n");


 /* тест номер twelve */
  memset( cipher, 0, plain_len );
  printf(" mgm example twelve for Magma (key form Annex.B, integrity only) ");
  result = ak_bckey_context_encrypt_mgm( NULL, &mkeyB, a, associated_len,
                                                     NULL, NULL, 0, iv64, sizeof(iv64), NULL, 8 );
  if( ak_error_get_value( ) != ak_error_ok ) printf("is Wrong\n");
    else printf("is Ok\n");

  /* printf(" cipher text: %s ", out = ak_ptr_to_hexstr( cipher, plain_len, ak_true )); free( out ); */
  if( result ) {
    printf("(icode: %s)\n\n", out = ak_buffer_to_hexstr( result, ak_true )); free( out );
    result = ak_buffer_delete( result );
  } else printf(" (mgm icode undefined)\n\n");

 ak_bckey_destroy( &mkeyA );
 ak_bckey_destroy( &mkeyB );
 ak_bckey_destroy( &kkeyA );
 ak_bckey_destroy( &kkeyB );

 return ak_libakrypt_destroy();
}
