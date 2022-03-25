/* ----------------------------------------------------------------------------------------------- */
/* Тестовый пример, иллюстрирующий работу c aead контекстом (для всех достукпных алгоритмов)

   test-aead.c                                                                                     */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

 /* тестовые данные */
 ak_uint8 apdata[41 + 67] = {
     0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
     0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
     0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0xEA,
    /* зашифровываем с этого момента */
     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
     0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
     0x00, 0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
     0x11, 0x00, 0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
     0xCC, 0xBB, 0xAA };

 static int testfunc( ak_aead actx, ak_function_aead *function, ak_oid oid,
                             ak_uint8 *iv, size_t iv_size, ak_uint8 *icodetest, size_t icode_size );

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
  int exitcode = EXIT_FAILURE;

 /* константные значения ключей из ГОСТ Р 34.13-2015 */
  ak_uint8 keyAnnexA[32] = {
     0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
     0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

  ak_uint8 keyAnnexB[32] = {
     0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

 /* синхропосылки */
  ak_uint8 iv128[16] = {
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
  ak_uint8 iv64[8] = {
    0x59, 0x0a, 0x13, 0x3c, 0x6b, 0xf0, 0xde, 0x92 };
  ak_uint8 icodeOne[16] = {
    0x57, 0x4E, 0x52, 0x01, 0xA8, 0x07, 0x26, 0x60, 0x66, 0xC6, 0xE9, 0x22, 0x57, 0x6B, 0x1B, 0x89 };
  ak_uint8 icodeTwo[8] = { 0xC5, 0x43, 0xDE, 0xF2, 0x4C, 0xB0, 0xC3, 0xF7 };
  ak_uint8 icodeThree[16] = {
    0x7d, 0xfd, 0xdb, 0xee, 0xaf, 0x61, 0x9e, 0x09, 0x03, 0xff, 0xe3, 0x36, 0x3f, 0xb0, 0x7b, 0x61 };
  ak_uint8 icodeFour[8] = { 0x50, 0x7f, 0x88, 0x75, 0x27, 0x9d, 0x57, 0x0d };

 /* контекст aead алгоритма */
  ak_oid oid = NULL;
  struct aead actx;

 /* по-умолчанию сообщения об ошибках выволятся в журналы syslog
    мы изменяем стандартный обработчик, на вывод сообщений в консоль */
  ak_log_set_level( ak_log_maximum );
  ak_libakrypt_create( ak_function_log_stderr );

 /* Тест №1. Используем алгоритм MGM-Кузнечик */
 /*  - 1. создаем контекст aead алгоритма, используя oid */
  if(( oid = ak_oid_find_by_name( "mgm-kuznechik" )) == NULL ) return EXIT_FAILURE;
  ak_aead_create_oid( &actx, ak_true, oid );
 /*  - 2. устанавливаем константные значения ключей шифрования и имитозащиты */
  oid->func.first.set_key( actx.encryptionKey , keyAnnexA, 32 );
  oid->func.second.set_key( actx.authenticationKey, keyAnnexB, 32 );
 /*  - 3. запускаем функцию тестирования режима работы */
  exitcode = testfunc( &actx, ak_bckey_encrypt_mgm, oid, iv128, 16, icodeOne, 16 );
  ak_aead_destroy( &actx );
  if( exitcode == EXIT_FAILURE ) goto exit;

 /* Тест №2. Используем алгоритм MGM-Магма */
 /*  - 1. создаем контекст aead алгоритма, используя oid */
  if(( oid = ak_oid_find_by_name( "mgm-magma" )) == NULL ) return EXIT_FAILURE;
  ak_aead_create_oid( &actx, ak_true, oid );
 /*  - 2. устанавливаем константные значения ключей шифрования и имитозащиты */
  oid->func.first.set_key( actx.encryptionKey , keyAnnexB, 32 );
  oid->func.second.set_key( actx.authenticationKey, keyAnnexA, 32 );
 /*  - 3. запускаем функцию тестирования режима работы */
  exitcode = testfunc( &actx, ak_bckey_encrypt_mgm, oid, iv64, 8, icodeTwo, 8 );
  ak_aead_destroy( &actx );
  if( exitcode == EXIT_FAILURE ) goto exit;

 /* Тест №3. Используем алгоритм XTSMAC-Кузнечик */
 /*  - 1. создаем контекст aead алгоритма, используя oid */
  if(( oid = ak_oid_find_by_name( "xtsmac-kuznechik" )) == NULL ) return EXIT_FAILURE;
  ak_aead_create_oid( &actx, ak_true, oid );
 /*  - 2. устанавливаем константные значения ключей шифрования и имитозащиты */
  oid->func.first.set_key( actx.encryptionKey , keyAnnexA, 32 );
  oid->func.second.set_key( actx.authenticationKey, keyAnnexB, 32 );
 /*  - 3. запускаем функцию тестирования режима работы */
  exitcode = testfunc( &actx, ak_bckey_encrypt_xtsmac, oid, iv128, 16, icodeThree, 16 );
  ak_aead_destroy( &actx );
  if( exitcode == EXIT_FAILURE ) goto exit;

 /* Тест №4. Используем алгоритм XTSMAC-Магма */
 /*  - 1. создаем контекст aead алгоритма, используя oid */
  if(( oid = ak_oid_find_by_name( "xtsmac-magma" )) == NULL ) return EXIT_FAILURE;
  ak_aead_create_oid( &actx, ak_true, oid );
 /*  - 2. устанавливаем константные значения ключей шифрования и имитозащиты */
  oid->func.first.set_key( actx.encryptionKey , keyAnnexB, 32 );
  oid->func.second.set_key( actx.authenticationKey, keyAnnexA, 32 );
 /*  - 3. запускаем функцию тестирования режима работы */
  exitcode = testfunc( &actx, ak_bckey_encrypt_xtsmac, oid, iv64, 8, icodeFour, 8 );
  ak_aead_destroy( &actx );
  if( exitcode == EXIT_FAILURE ) goto exit;


  exitcode = EXIT_SUCCESS;
 exit:
  ak_libakrypt_destroy();

 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
 static int testfunc( ak_aead actx, ak_function_aead *function, ak_oid oid,
                            ak_uint8 *iv, size_t iv_size, ak_uint8 *icodetest, size_t icode_size )
{
  ak_uint8 out[67];
  ak_uint8 icode[64];

  memset( out, 0, sizeof( out ));
  memset( icode, 0, sizeof( icode ));
 /*  - 1. зашифровываем, используя один вызов функции */
  function( actx->encryptionKey, actx->authenticationKey,
                                 apdata, 41, apdata +41, out, 67, iv, iv_size, icode, icode_size );

 /* проверяем тестовое значение имитовставки */
  if( !ak_ptr_is_equal_with_log( icode, icodetest, icode_size )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                        "the plain integrity code for %s is wrong", oid->name[0] );
    return EXIT_FAILURE;
  }
  printf("%s\n 1. %s\n", oid->name[0], ak_ptr_to_hexstr( out, sizeof( out ), ak_false ));

 /*  - 2. зашифровываем, используя пошаговые вычисления */
  memset( out, 0, sizeof( out ));
  memset( icode, 0, sizeof( icode ));
  actx->auth_clean( actx->ictx, actx->authenticationKey, iv, iv_size );
  actx->enc_clean( actx->ictx, actx->encryptionKey, iv, iv_size );
  /* усложняем вызов
     actx.auth_update( actx.ictx, actx.authenticationKey, apdata, 41 ); */
  actx->auth_update( actx->ictx, actx->authenticationKey, apdata, 32 ); /* используем длину, кратную длине входного блока */
  actx->auth_update( actx->ictx, actx->authenticationKey, apdata +32, 9 );
  /* усложняем вызов
     actx.enc_update( actx.ictx, actx.encryptionKey, actx.authenticationKey, apdata +41, out, 67 ); */
  actx->enc_update( actx->ictx, actx->encryptionKey, actx->authenticationKey, apdata +41, out, 32 );
  actx->enc_update( actx->ictx, actx->encryptionKey, actx->authenticationKey, apdata +41 +32, out +32, 35 );
  actx->auth_finalize( actx->ictx, actx->authenticationKey, icode, icode_size );
 /* проверяем тестовое значение имитовставки */
  if( !ak_ptr_is_equal_with_log( icode, icodetest, icode_size )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                            "the integrity code for two kuznechik keys is wrong" );
    return EXIT_FAILURE;
  }
  printf(" 2. %s\n", ak_ptr_to_hexstr( out, sizeof( out ), ak_false ));

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    test-aead.c  */
/* ----------------------------------------------------------------------------------------------- */

