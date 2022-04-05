/* ----------------------------------------------------------------------------------------------- */
/* Тестовый пример, иллюстрирующий работу c aead контекстом (для всех доступных алгоритмов)

   test-aead.c                                                                                     */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

 /* константные значения ключей из ГОСТ Р 34.13-2015 */
  ak_uint8 keyAnnexA[32] = {
     0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
     0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

  ak_uint8 keyAnnexB[32] = {
     0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

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

 /* тестовые синхропосылки */
  ak_uint8 iv[32] = {
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    0x59, 0x0a, 0x13, 0x3c, 0x6b, 0xf0, 0xde, 0x92, 0x21, 0x43, 0x65, 0x87, 0xa9, 0xcb, 0xed, 0x0f };

/* ----------------------------------------------------------------------------------------------- */
 int testfunc_2key( ak_oid oid, ak_uint8 *icodetest, size_t icode_size )
{
  struct aead ctx;
  ak_uint8 icode[64];
  size_t shift, tail, blocks;
  int error, exitcode = EXIT_FAILURE;

 /* создаем контекст согласно поданному oid и присваиваем константные значения */
  if( ak_aead_create_oid( &ctx, ak_true, oid ) != ak_error_ok ) return EXIT_FAILURE;

 /* присваиваем ключевые значения (тестируем все доступные функции) */
  if(( error = ak_aead_set_keys( &ctx, keyAnnexB, 32, keyAnnexA, 32 )) != ak_error_ok ) {
    ak_error_message( error, __func__, "ошибка присвоения ключевых значений" );
    goto exlab;
  }

 /* начинаем тестирование с того, что проверяем прямой вызов функций шифрования/расшифрования */
  memset( icode, 0, sizeof( icode ));
  if(( error = ak_aead_encrypt( &ctx,
                    apdata,
                    41,
                    apdata +41,
                    apdata +41,
                    67,
                    iv,
                    ctx.iv_size,
                    icode,
                    icode_size )) != ak_error_ok ) {
    ak_error_message( error, __func__, "ошибка зашифрования данных" );
    goto exlab;
  }
 /* проверяем тестовое значение имитовставки */
  if( !ak_ptr_is_equal_with_log( icode, icodetest, icode_size )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ , "неверная контрольная сумма" );
    goto exlab;
  }
  printf("%s (%s)\n", oid->name[0], ak_ptr_to_hexstr( icodetest, icode_size, ak_false ));
  printf(" 1. %s ", ak_ptr_to_hexstr( apdata +41, 67, ak_false )); fflush( stdout );

 /* расшифровываем */
  if(( error = ak_aead_decrypt( &ctx,
                    apdata,
                    41,
                    apdata +41,
                    apdata +41,
                    67,
                    iv,
                    ctx.iv_size,
                    icode, /* сравниваем с вычисленным ранее значением */
                    icode_size )) != ak_error_ok ) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ , "ошибка при расшифровании" );
    goto exlab;
  }
  printf("Ok\n");

 /* теперь выполняем поблоковое зашифрование информации:
    мы нарезаем ассоциированные даные и шифртекст на блоки фиксированной длины,
    после чего, выполняем обновление (update) внутреннего состояния aead котекста */
  shift = 0;
  blocks = 41/ctx.block_size;
  memset( icode, 0, sizeof( icode ));
  ak_aead_auth_clean( &ctx, iv, ctx.iv_size );
  for( size_t i = 0; i < blocks; i++, shift += ctx.block_size ) {
    ak_aead_auth_update( &ctx, apdata +shift, ctx.block_size );
  }
  if(( tail = 41%ctx.block_size ) > 0 ) ak_aead_auth_update( &ctx, apdata +shift, tail );

  shift = 0;
  blocks = 67/ctx.block_size;
  ak_aead_encrypt_clean( &ctx, iv, ctx.iv_size );
  for( size_t i = 0; i < blocks; i++, shift += ctx.block_size ) {
    ak_aead_encrypt_update( &ctx, apdata +41 +shift, apdata +41 +shift, ctx.block_size );
  }
  if(( tail = 67%ctx.block_size ) > 0 )
    ak_aead_encrypt_update( &ctx, apdata +41 +shift, apdata +41 +shift, tail );
  ak_aead_finalize( &ctx, icode, icode_size );

 /* проверяем тестовое значение имитовставки */
  if( !ak_ptr_is_equal_with_log( icode, icodetest, icode_size )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ , "неверная контрольная сумма" );
    goto exlab;
  }
  printf(" 2. %s ", ak_ptr_to_hexstr( apdata +41, 67, ak_false ));

 /* расшифровываем данные,
    используя минимально возможное количество вызовов функций обновления контента */
  memset( icode, 0, sizeof( icode ));
  ak_aead_clean( &ctx, iv, ak_aead_get_iv_size( &ctx )); // ctx.iv_size
  tail = 41%ak_aead_get_block_size( &ctx );
  if(( shift = 41 - tail ) > 0) ak_aead_auth_update( &ctx, apdata, shift );
  if( tail ) ak_aead_auth_update( &ctx, apdata +shift, tail );

  tail = 67%ak_aead_get_block_size( &ctx );;
  if(( shift = 67 - tail ) > 0) ak_aead_decrypt_update( &ctx, apdata +41, apdata +41, shift );
  if( tail ) ak_aead_decrypt_update( &ctx, apdata +41 +shift, apdata +41 +shift, tail );
  ak_aead_finalize( &ctx, icode, icode_size );

 /* проверяем тестовое значение имитовставки */
  if( !ak_ptr_is_equal_with_log( icode, icodetest, icode_size )) {
    printf("Wrong\n");
    ak_error_message_fmt( ak_error_not_equal_data, __func__ , "неверная контрольная сумма" );
    goto exlab;
  }
  printf("Ok\n");

  exitcode = EXIT_SUCCESS;
  exlab:
    ak_aead_destroy( &ctx );

 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
 int testfunc_1key( ak_oid oid, ak_uint8 *icodetest, size_t icode_size )
{
  size_t tail;
  struct aead ctx;
  ak_uint8 icode[64];
  int error, exitcode = EXIT_FAILURE;

 /* создаем контекст согласно поданному oid и присваиваем константные значения */
  if( ak_aead_create_oid( &ctx, ak_false, oid ) != ak_error_ok ) return EXIT_FAILURE;

 /* присваиваем ключ атентификации */
  if(( error = ak_aead_set_auth_key( &ctx, keyAnnexA, 32 )) != ak_error_ok ) {
    ak_error_message( error, __func__, "ошибка присвоения ключевого значения" );
    goto exlab;
  }

 /* вычисление имитовставки (по частям) */
  memset( icode, 0, icode_size );
  ak_aead_auth_clean( &ctx, iv, ctx.iv_size );
  tail = ak_max( 32, ctx.block_size );
  ak_aead_auth_update( &ctx, apdata, tail );
  ak_aead_encrypt_update( &ctx, apdata +tail, NULL, sizeof( apdata ) -tail );
  ak_aead_finalize( &ctx, icode, icode_size );

  if( !ak_ptr_is_equal_with_log( icode, icodetest, icode_size )) {
    printf(" 3. divided mac not supported (%s, compare with next value)\n",
                                                   ak_ptr_to_hexstr( icode, icode_size, ak_false));
  }
   else printf(" 3. divided mac is Ok (%s)\n", ak_ptr_to_hexstr( icode, icode_size, ak_false));

 /* вычисление имитовставки (за один вызов) */
  memset( icode, 0, sizeof( icode ));
  if(( error = ak_aead_mac( &ctx,
                    apdata,
                    41 + 67,
                    iv,
                    ctx.iv_size,
                    icode,
                    icode_size )) != ak_error_ok ) {
    ak_error_message( error, __func__, "ошибка зашифрования данных" );
    goto exlab;
  }
 /* проверяем тестовое значение имитовставки */
  printf(" 4. mac (%s)\n", ak_ptr_to_hexstr( icode, icode_size, ak_false ));

 /* вычисление имитовставки (по частям) */
  memset( icode, 0, icode_size );
  ak_aead_auth_clean( &ctx, iv, ctx.iv_size );
  ak_aead_auth_update( &ctx, apdata, sizeof( apdata ));
  ak_aead_finalize( &ctx, icode, icode_size );
  printf(" 4. mac (%s)\n", ak_ptr_to_hexstr( icode, icode_size, ak_false ));

  exitcode = EXIT_SUCCESS;
  exlab:
    ak_aead_destroy( &ctx );

 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
 int testfunc( ak_oid oid, ak_uint8 *icodetest, size_t icode_size )
{
   printf("aead: %s (%s)\n", oid->name[0], oid->id[0] );

   if( testfunc_2key( oid, icodetest, icode_size ) != EXIT_SUCCESS ) return EXIT_FAILURE;
   if( testfunc_1key( oid, icodetest, icode_size ) != EXIT_SUCCESS ) return EXIT_FAILURE;
   printf("\n");
 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
  struct bckey bctx;
  int exitcode = EXIT_FAILURE;

  ak_uint8 icode_mgm_magma[8] = { 0xd6, 0xad, 0x80, 0x04, 0x60, 0x60, 0xbc, 0x36};
  ak_uint8 icode_mgm_kuznechik[16] =
   { 0xa6, 0xf2, 0xdc, 0x82, 0x76, 0x1e, 0x0a, 0xc2, 0x31, 0x7d, 0x19, 0x49, 0x2e, 0xf6, 0x93, 0xfa };
  ak_uint8 icode_ctr_cmac_magma[8] = { 0x00 };
  ak_uint8 icode_ctr_cmac_kuznechik[16] = { 0x00 };
  ak_uint8 icode_xtsmac_magma[16] = { 0x00 };
  ak_uint8 icode_xtsmac_kuznechik[16] = { 0x00 };

 /* по-умолчанию сообщения об ошибках выволятся в журналы syslog
    мы изменяем стандартный обработчик, на вывод сообщений в консоль */
  ak_log_set_level( ak_log_maximum );
  ak_libakrypt_create( ak_function_log_stderr );

 /* тестируем режим работы ctr-cmac-magma */
 /* - формируем контрольное значение имитовставки */
  ak_bckey_create_magma( &bctx );
  ak_bckey_set_key( &bctx, keyAnnexA, 32 );
  ak_bckey_cmac( &bctx, apdata, 41+67, icode_ctr_cmac_magma, 8 );
  ak_bckey_destroy( &bctx );
// /* - проверяем корректность вычислений с aead контекстом */
  exitcode = testfunc( ak_oid_find_by_name( "ctr-cmac-magma" ), icode_ctr_cmac_magma, 8 );
  if( exitcode == EXIT_FAILURE ) goto exit;

 /* тестируем режим работы ctr-cmac-kuznechik */
 /* - формируем контрольное значение имитовставки */
  ak_bckey_create_kuznechik( &bctx );
  ak_bckey_set_key( &bctx, keyAnnexA, 32 );
  ak_bckey_cmac( &bctx, apdata, 41+67, icode_ctr_cmac_kuznechik, 16 );
  ak_bckey_destroy( &bctx );
 /* - проверяем корректность вычислений с aead контекстом */
  exitcode = testfunc( ak_oid_find_by_name( "ctr-cmac-kuznechik" ), icode_ctr_cmac_kuznechik, 16 );
  if( exitcode == EXIT_FAILURE ) goto exit;

 /* тестируем режим работы mgm-magma */
  exitcode = testfunc( ak_oid_find_by_name( "mgm-magma" ), icode_mgm_magma, 8 );
  if( exitcode == EXIT_FAILURE ) goto exit;

 /* тестируем режим работы mgm-kuznechik */
  exitcode = testfunc( ak_oid_find_by_name( "mgm-kuznechik" ), icode_mgm_kuznechik, 16 );
  if( exitcode == EXIT_FAILURE ) goto exit;

// /* тестируем режим работы xtsmac-magma */
//  exitcode = testfunc( ak_oid_find_by_name( "xtsmac-magma" ), icode_xtsmac_magma, 16 );
//  if( exitcode == EXIT_FAILURE ) goto exit;

// /* тестируем режим работы xtsmac-magma */
//  exitcode = testfunc( ak_oid_find_by_name( "xtsmac-kuznechik" ), icode_xtsmac_kuznechik, 16 );
//  if( exitcode == EXIT_FAILURE ) goto exit;

 /* завершаем выполнение теста */
  exitcode = EXIT_SUCCESS;
 exit:
  ak_libakrypt_destroy();

 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    test-aead.c  */
/* ----------------------------------------------------------------------------------------------- */
