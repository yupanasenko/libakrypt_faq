/* ----------------------------------------------------------------------------------------------- */
/* Тестовый пример, иллюстрирующий работу c aead контекстом (для всех достукпных алгоритмов)

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
  ak_uint8 iv128[16] = {
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
  ak_uint8 iv64[8] = {
    0x59, 0x0a, 0x13, 0x3c, 0x6b, 0xf0, 0xde, 0x92 };

/* ----------------------------------------------------------------------------------------------- */
 int testfunc( ak_oid oid, ak_uint8 *icodetest, size_t icode_size )
{
  struct aead ctx;
  size_t shift, tail, blocks;
  ak_uint8 icode[64], icode2[64];
  int error, exitcode = EXIT_FAILURE;

 /* создаем контекст согласно поданному oid и присваиваем константные значения */
  if( ak_aead_create_oid( &ctx, ak_true, oid ) != ak_error_ok ) return EXIT_FAILURE;

 /* присваиваем ключевые значения (тестируем все доступные функции) */
  if( ctx.tag_size == 8 ) { /* для режимов на основе Магмы */
    if(( error = ak_aead_set_keys( &ctx, keyAnnexB, 32, keyAnnexA, 32 )) != ak_error_ok ) {
      ak_error_message( error, __func__, "ошибка присвоения ключевых значений" );
      goto exlab;
    }
  } else {
    if(( error = ak_aead_set_encrypt_key( &ctx, keyAnnexA, 32 )) != ak_error_ok ) {
      ak_error_message( error, __func__, "ошибка присвоения значения ключу шифрования" );
      goto exlab;
    }
    if(( error = ak_aead_set_auth_key( &ctx, keyAnnexB, 32 )) != ak_error_ok ) {
      ak_error_message( error, __func__, "ошибка присвоения значения ключу аутентификации" );
      goto exlab;
    }
   }

 /* начинаем тестирование с того, что проверяем прямой вызов функций шифрования/расшифрования */
  memset( icode, 0, sizeof( icode ));
  oid->func.direct( ctx.encryptionKey,
                    ctx.authenticationKey,
                    apdata,
                    41,
                    apdata +41,
                    apdata +41,
                    67,
                    ctx.tag_size == 8 ? iv64 : iv128,
                    ctx.tag_size,
                    icode,
                    icode_size );
 /* проверяем тестовое значение имитовставки */
  if( !ak_ptr_is_equal_with_log( icode, icodetest, icode_size )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ , "неверная контрольная сумма" );
    goto exlab;
  }
  printf("%s (%s)\n", oid->name[0], ak_ptr_to_hexstr( icodetest, icode_size, ak_false ));
  printf(" 1. %s\n", ak_ptr_to_hexstr( apdata +41, 67, ak_false ));

 /* расшифровываем */
  if(( error = oid->func.invert(
                    ctx.encryptionKey,
                    ctx.authenticationKey,
                    apdata,
                    41,
                    apdata +41,
                    apdata +41,
                    67,
                    ctx.tag_size == 8 ? iv64 : iv128,
                    ctx.tag_size,
                    icode, /* сравниваем с вычисленным ранее значением */
                    icode_size )) != ak_error_ok ) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ , "ошибка при расшифровании" );
    goto exlab;
  }

 /* зашифровываем, используя пошаговые вычисления */
  memset( icode, 0, sizeof( icode ));
  ak_aead_clean( &ctx, ctx.tag_size == 8 ? iv64 : iv128, ctx.tag_size );

/* быстрый способ обработки может быть реализован так:

    tail = 41%ctx.block_size;
    if(( shift = 41 - tail) > 0 ) ak_aead_auth_update( &ctx, apdata, shift );
    if( tail ) ak_aead_auth_update( &ctx, apdata +shift, tail );

    приведенный выше фрагмент кода используется далее при расшифровании данных,
    сейчас же мы используем поблочную обработку данных */

  shift = 0;
  for( size_t i = 0; i < ( blocks = 41/ctx.block_size ); i++ ) {
    ak_aead_auth_update( &ctx, apdata +shift, ctx.block_size );
    shift += ctx.block_size;
  }
  if(( tail = 41%ctx.block_size ) > 0 ) ak_aead_auth_update( &ctx, apdata +shift, tail );

 /* теперь зашифровываем данные */
  shift = 0;
  for( size_t i = 0; i < ( blocks = 67/ctx.block_size ); i++ ) {
    ak_aead_encrypt_update( &ctx, apdata +41 +shift, apdata +41 +shift, ctx.block_size );
    shift += ctx.block_size;
  }
  if(( tail = 67%ctx.block_size ) > 0 )
    ak_aead_encrypt_update( &ctx, apdata +41 +shift, apdata +41 +shift, tail );
  ak_aead_auth_finalize( &ctx, icode, icode_size );

 /* проверяем тестовое значение имитовставки */
  if( !ak_ptr_is_equal_with_log( icode, icodetest, icode_size )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ , "неверная контрольная сумма" );
    goto exlab;
  }
  printf(" 2. %s\n", ak_ptr_to_hexstr( apdata +41, 67, ak_false ));

 /* расшифровываем, используя пошаговые вычисления */
  memset( icode, 0, sizeof( icode ));
  ak_aead_clean( &ctx, ctx.tag_size == 8 ? iv64 : iv128, ctx.tag_size );

  tail = 41%ctx.block_size;
  if(( shift = 41 - tail) > 0 ) ak_aead_auth_update( &ctx, apdata, shift );
  if( tail ) ak_aead_auth_update( &ctx, apdata +shift, tail );

  tail = 67%ctx.block_size;
  if(( shift = 67 - tail) > 0 ) ak_aead_decrypt_update( &ctx, apdata +41, apdata +41, shift );
  if( tail ) ak_aead_decrypt_update( &ctx, apdata +41 +shift, apdata +41 +shift, tail );
  ak_aead_auth_finalize( &ctx, icode, icode_size );
 /* проверяем тестовое значение имитовставки */
  if( !ak_ptr_is_equal_with_log( icode, icodetest, icode_size )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ , "неверная контрольная сумма" );
    goto exlab;
  }
  printf(" 3. decrypt Ok\n");
  exlab:
    ak_aead_destroy( &ctx );

 /* в заключение, тестируем функцию имитозащиты (без создания ключа шифрования в контенксте aead) */
  if( ak_aead_create_oid( &ctx, ak_false, oid ) != ak_error_ok ) return EXIT_FAILURE;
 /* присваиваем значение ключу имитозащиты */
  if( ctx.tag_size == 8 ) { /* для режимов на основе Магмы */
    if(( error = ak_aead_set_auth_key( &ctx, keyAnnexA, 32 )) != ak_error_ok ) {
      ak_error_message( error, __func__, "ошибка присвоения значения ключу аутентификации" );
      goto exlab2;
    }
  } else {
    if(( error = ak_aead_set_auth_key( &ctx, keyAnnexB, 32 )) != ak_error_ok ) {
      ak_error_message( error, __func__, "ошибка присвоения значения ключу аутентификации" );
      goto exlab2;
    }
   }

 /* в начале, пошаговое вычисление имитовставки от двух половинок текста (без шифрования) */
  memset( icode, 0, sizeof( icode ));
  ak_aead_auth_clean( &ctx, ctx.tag_size == 8 ? iv64 : iv128, ctx.tag_size );
  tail = ak_max( 32, ctx.tag_size );
  ak_aead_auth_update( &ctx, apdata, tail );
  ak_aead_encrypt_update( &ctx, apdata +tail, NULL, sizeof( apdata ) -tail );
  ak_aead_auth_finalize( &ctx, icode, icode_size );
 /* проверяем тестовое значение имитовставки, должно совпадать
    либо с предыдущим, либо с тем, что будет далее )) */
  if( !ak_ptr_is_equal( icode, icodetest, icode_size )) {
    printf(" 4. divided mac not supported (%s, compare with next values)\n",
                                            ak_ptr_to_hexstr( icode, icode_size, ak_false ));
  }
   else printf(" 4. divided mac (%s) Ok\n", ak_ptr_to_hexstr( icode, icode_size, ak_false ));

 /* потом, прямое вычисление имитовставки */
  memset( icode, 0, sizeof( icode ));
  oid->func.direct( NULL,
                    ctx.authenticationKey,
                    apdata,
                    41 + 67,
                    NULL,
                    NULL,
                    0,
                    ctx.tag_size == 8 ? iv64 : iv128,
                    ctx.tag_size,
                    icode,
                    icode_size );
  printf(" 5. mac: %s\n", ak_ptr_to_hexstr( icode, icode_size, ak_false ));

 /* в заключение, последовательное вычисление имитовставки */
  memset( icode2, 0, sizeof( icode ));
  ak_aead_auth_clean( &ctx, ctx.tag_size == 8 ? iv64 : iv128, ctx.tag_size );
  ak_aead_auth_update( &ctx, apdata, 41+67 );
  ak_aead_auth_finalize( &ctx, icode2, icode_size );
  printf(" 6. mac: %s ", ak_ptr_to_hexstr( icode2, icode_size, ak_false ));
 /* сравниваем вычисленые двумя способами имитовставки */
  if( !ak_ptr_is_equal_with_log( icode, icode2, icode_size )) {
    ak_error_message_fmt( ak_error_not_equal_data, __func__ , "неверная контрольная сумма" );
    printf("Wrong\n");
    goto exlab2;
  }
  printf("Ok\n\n");

  exitcode = EXIT_SUCCESS;
  exlab2:
    ak_aead_destroy( &ctx );

 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
  int exitcode = EXIT_FAILURE;

  ak_uint8 icode_mgm_magma[8] = { 0xC5, 0x43, 0xDE, 0xF2, 0x4C, 0xB0, 0xC3, 0xF7 };
  ak_uint8 icode_mgm_kuznechik[16] = {
    0x57, 0x4E, 0x52, 0x01, 0xA8, 0x07, 0x26, 0x60, 0x66, 0xC6, 0xE9, 0x22, 0x57, 0x6B, 0x1B, 0x89 };
  ak_uint8 icode_ctr_cmac_magma[8] = { 0xdf, 0xdb, 0x24, 0x1f, 0x0b, 0x9f, 0x5e, 0x63 };
  ak_uint8 icode_ctr_cmac_kuznechik[16] = {
    0xad, 0x86, 0xb9, 0x16, 0xe9, 0x42, 0xbd, 0x45, 0x0e, 0xba, 0xcb, 0x50, 0xd6, 0x0b, 0x68, 0x4c };
  ak_uint8 icode_xtsmac_magma[8] = { 0x50, 0x7f, 0x88, 0x75, 0x27, 0x9d, 0x57, 0x0d };

 /* по-умолчанию сообщения об ошибках выволятся в журналы syslog
    мы изменяем стандартный обработчик, на вывод сообщений в консоль */
  ak_log_set_level( ak_log_maximum );
  ak_libakrypt_create( ak_function_log_stderr );

 /* тестируем режим работы ctr-cmac-magma */
  exitcode = testfunc( ak_oid_find_by_name( "ctr-cmac-magma" ), icode_ctr_cmac_magma, 8 );
  if( exitcode == EXIT_FAILURE ) goto exit;

 /* тестируем режим работы ctr-cmac-kuznechik */
  exitcode = testfunc( ak_oid_find_by_name( "ctr-cmac-kuznechik" ), icode_ctr_cmac_kuznechik, 16 );
  if( exitcode == EXIT_FAILURE ) goto exit;

 /* тестируем режим работы mgm-kuznechik */
  exitcode = testfunc( ak_oid_find_by_name( "mgm-magma" ), icode_mgm_magma, 8 );
  if( exitcode == EXIT_FAILURE ) goto exit;

 /* тестируем режим работы mgm-kuznechik */
  exitcode = testfunc( ak_oid_find_by_name( "mgm-kuznechik" ), icode_mgm_kuznechik, 16 );
  if( exitcode == EXIT_FAILURE ) goto exit;

 /* завершаем выполнение теста */
  exitcode = EXIT_SUCCESS;
 exit:
  ak_libakrypt_destroy();

 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    test-aead.c  */
/* ----------------------------------------------------------------------------------------------- */
