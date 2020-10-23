 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <aktool.h>

/* ----------------------------------------------------------------------------------------------- */
/* - запуск теста криптографических алгоритмов
       aktool test --crypto --audit 2 --audit-file stderr                                          */
/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_help( void );

 int aktool_test_speed_encryption( ak_oid );
 int aktool_test_speed_encryption2k( ak_oid );
 int aktool_test_speed_acpkm( ak_oid );
 int aktool_test_speed_mac( ak_oid );
 int aktool_test_speed_aead( ak_oid );
 int aktool_test_speed_block_cipher( ak_oid );

/* ----------------------------------------------------------------------------------------------- */
  bool_t aktool_test_verbose = ak_false;

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test( int argc, tchar *argv[] )
{
  ak_oid oid = NULL;
  char *value = NULL;
  int next_option = 0, exit_status = EXIT_SUCCESS;

  enum { do_nothing, do_dynamic, do_speed_oid } work = do_nothing;

  const struct option long_options[] = {
     { "crypto",           0, NULL, 255 },
     { "speed",            1, NULL, 254 },
     { "verbose",          0, NULL, 'v' },

     { "openssl-style",    0, NULL,   5 },
     { "audit",            1, NULL,   4 },
     { "dont-use-colors",  0, NULL,   3 },
     { "audit-file",       1, NULL,   2 },
     { "help",             0, NULL,   1 },
     { NULL,               0, NULL,   0 }
  };

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "v", long_options, NULL );
       switch( next_option )
      {
        case  1  :   return aktool_test_help();
        case  2  : /* получили от пользователя имя файла для вывода аудита */
                     aktool_set_audit( optarg );
                     break;
        case  3  : /* установка флага запрета вывода символов смены цветовой палитры */
                     ak_error_set_color_output( ak_false );
                     ak_libakrypt_set_option( "use_color_output", 0 );
                     break;
        case  4  : /* устанавливаем уровень аудита */
                     aktool_log_level = atoi( optarg );
                     break;
        case  5  : /* переходим к стилю openssl */
                     aktool_openssl_compability = ak_true;
                     break;

        case 'v' : /* расширенный вывод иформации о происходящем */
                     aktool_test_verbose = ak_true;
                     break;

        case 255 : /* тест скорости функций хеширования */
                     work = do_dynamic;
                     break;

        case 254 : /* тест скорости по заданному идентификатору алгоритма */
                     work = do_speed_oid; value = optarg;
                     break;

        default:   /* обрабатываем ошибочные параметры */
                     if( next_option != -1 ) work = do_nothing;
                     break;
       }
   } while( next_option != -1 );
   if( work == do_nothing ) return aktool_test_help();

 /* начинаем работу с криптографическими примитивами */
   if( !aktool_create_libakrypt( )) return EXIT_FAILURE;

 /* выбираем заданное пользователем действие */
    switch( work )
   {
     case do_dynamic:
       if( ak_libakrypt_dynamic_control_test( )) printf(_("complete crypto test is Ok\n"));
        else {
          printf(_("complete crypto test is Wrong\n"));
          exit_status = EXIT_FAILURE;
        }
       break;

     case do_speed_oid:
       if(( oid = ak_oid_find_by_ni( value )) == NULL ) {
         printf(_("using unsupported name or identifier \"%s\"\n\n"), value );
         printf(_("try \"aktool show --oids\" for list of all available identifiers\n"));
         exit_status = EXIT_FAILURE;
         break;
       }       
       switch( oid->engine ) {
        case block_cipher: /* разбор алгоритмов для блочного шифрования */
           switch( oid->mode ) {
             case aead: exit_status = aktool_test_speed_aead( oid );
               break;
             case encryption: exit_status = aktool_test_speed_encryption( oid );
               break;
             case encryption2k: exit_status = aktool_test_speed_encryption2k( oid );
               break;
             case mac: exit_status = aktool_test_speed_mac( oid );
               break;
             case acpkm: exit_status = aktool_test_speed_acpkm( oid );
               break;
             case algorithm: exit_status = aktool_test_speed_block_cipher( oid );
               break;
             default:
               printf(_("block cipher mode \"%s\" is not supported yet for testing, sorry ... \n"),
                                                           ak_libakrypt_get_mode_name( oid->mode ));
               exit_status = EXIT_SUCCESS;
               break;
           }
           break;

         default:
           printf(_("algorithm engine \"%s\" is not supported yet for testing, sorry ... \n"),
                                                       ak_libakrypt_get_engine_name( oid->engine ));
           exit_status = EXIT_SUCCESS;
       }
       break; /* конец do_speed_oid */

     default:  break;
   }
   if( exit_status == EXIT_FAILURE )
     printf(_("for more information run tests with \"--audit 2 --audit-file stderr\" options or see /var/log/auth.log file\n"));

 /* завершаем работу и выходим */
   aktool_destroy_libakrypt();

 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_help( void )
{
  printf(
   _("aktool test [options]  - run various tests\n\n"
     "available options:\n"
     "     --crypto            complete test of cryptographic algorithms\n"
     "                         run all available algorithms on test values taken from standards and recommendations\n"
     "     --speed <ni>        measuring the speed of the crypto algorithm with a given name or identifier\n"
     " -v, --verbose           detailed information output\n"
     "\n"
     "for more information run tests with \"--audit 2 --audit-file stderr\" options or see /var/log/auth.log file\n"
  ));

 return aktool_print_common_options();
}

/* ----------------------------------------------------------------------------------------------- */
/*                      далее множество однотипных функций тестирования                            */
/* ----------------------------------------------------------------------------------------------- */
 static ak_uint8 iv[48] = {
    0x12, 0x01, 0xf0, 0xe5, 0xd4, 0xc3, 0xb2, 0xa1, 0xf0, 0xce, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12,
    0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x90, 0x89, 0x78, 0x67, 0x56, 0x45, 0x34, 0x23,
    0xe9, 0xa8, 0x11, 0x12, 0x4c, 0x1b, 0x01, 0x1f, 0xf0, 0x87, 0xac, 0xab, 0x53, 0x19, 0x7d, 0xd1
  };

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_speed_encryption( ak_oid oid )
{
  clock_t timea;
  size_t size = 0;
  double iter = 0, avg = 0;
  ak_uint8 *data;
  int i, error = ak_error_ok, exit_status = EXIT_FAILURE;
  ak_pointer encryptionKey = NULL;

  printf(_("testing speed of %s (%s) algorithm\n"), oid->name[0], oid->id[0] );

 /* создаем ключи */
  if(( encryptionKey = ak_oid_new_object( oid )) == NULL ) {
    aktool_error( _("incorrect creation of encryption key (%d)" ), ak_error_get_value( ));
    goto exit;
  }

 /* приваиваем ключам значения */
  if(( error = ((ak_function_set_key_object *)oid->func.first.set_key)
                                                   ( encryptionKey, iv+16, 32 )) != ak_error_ok ) {
     aktool_error( _("incorrect assigning encryption key value (%d)" ), error );
     goto exit;
  }
  if( !aktool_test_verbose ) { printf(_("[16MB ")); fflush( stdout ); }

 /* теперь собственно тестирование скорости реализации */
  for( i = 16; i < 129; i += 8 ) {
    data = malloc( size = ( size_t ) i*1024*1024 );
    memset( data, (ak_uint8)i+13, size );

   /* на очень больших объемах одного ключа мало, надо увеличивать ресурс */
   /* далее - не очень хороший стиль, мы пользуемся тем,
      что все ключевые структуры содержат ключ первым элементом структуры */
    ((ak_skey)encryptionKey)->resource.value.counter = size;

    timea = clock();
    error = ( oid->func.direct )(
      encryptionKey,     /* ключ шифрования */
      data,              /* указатель на зашифровываемые данные */
      data,              /* указатель на зашифрованные данные */
      size,              /* размер шифруемых данных */
      iv,                /* синхропосылка для режима гаммирования */
      sizeof( iv )       /* доступный размер синхропосылки */
    );
    timea = clock() - timea;
    if( error != ak_error_ok ) {
      aktool_error(_("computational error (%d)"), error );
      if( data ) free( data );
      goto exit;
    }

    if( aktool_test_verbose )
      printf(_(" %3uMB: encryption time: %fs, per 1MB = %fs, speed = %f MBs\n"), (unsigned int)i,
               (double) timea / (double) CLOCKS_PER_SEC,
               (double) timea / ( (double) CLOCKS_PER_SEC*i ),
               (double) CLOCKS_PER_SEC*i / (double) timea );
     else { printf("."); fflush( stdout ); }

    if( i > 16 ) {
      iter += 1;
      avg += (double) CLOCKS_PER_SEC*i / (double) timea;
    }
    free( data );
  }

  if( !aktool_test_verbose ) printf(_(" 128MB],"));
  printf(_(" average speed: %10f MBs\n"), avg/iter );

  exit_status = EXIT_SUCCESS;
  exit:
   ak_oid_delete_object( oid, encryptionKey );

 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_speed_encryption2k( ak_oid oid )
{
  clock_t timea;
  size_t size = 0;
  double iter = 0, avg = 0;
  ak_uint8 *data;
  int i, error = ak_error_ok, exit_status = EXIT_FAILURE;
  ak_pointer encryptionKey = NULL, authenticationKey = NULL;

  printf(_("testing speed of %s (%s) algorithm\n"), oid->name[0], oid->id[0] );

 /* создаем ключи */
  if(( encryptionKey = ak_oid_new_object( oid )) == NULL ) {
    aktool_error( _("incorrect creation of encryption key (%d)" ), ak_error_get_value( ));
    goto exit;
  }
  if(( authenticationKey = ak_oid_new_second_object( oid )) == NULL ) {
    aktool_error( _("incorrect creation of authentication key (%d)" ), ak_error_get_value( ));
    goto exit;
  }

 /* приваиваем ключам значения */
  if(( error = ((ak_function_set_key_object *)oid->func.first.set_key)
                                                   ( encryptionKey, iv+16, 32 )) != ak_error_ok ) {
     aktool_error( _("incorrect assigning encryption key value (%d)" ), error );
     goto exit;
  }
  if(( error = ((ak_function_set_key_object *)oid->func.second.set_key)
                                                  ( authenticationKey, iv, 32 )) != ak_error_ok ) {
     aktool_error(_("incorrect assigning authentication key value (%d)" ), error );
     goto exit;
  }
  if( !aktool_test_verbose ) { printf(_("[16MB ")); fflush( stdout ); }

 /* теперь собственно тестирование скорости реализации */
  for( i = 16; i < 129; i += 8 ) {
    data = malloc( size = ( size_t ) i*1024*1024 );
    memset( data, (ak_uint8)i+1, size );

   /* на очень больших объемах одного ключа мало, надо увеличивать ресурс */
   /* далее - не очень хороший стиль, мы пользуемся тем,
      что все ключевые структуры содержат ключ первым элементом структуры */
    ((ak_skey)authenticationKey)->resource.value.counter = size;
    ((ak_skey)encryptionKey)->resource.value.counter = size;

    timea = clock();
    error =
    ( oid->func.direct )(
      encryptionKey,     /* ключ шифрования */
      authenticationKey, /* ключ имитозащиты */
      data,              /* указатель на зашифровываемые данные */
      data,              /* указатель на зашифрованные данные */
      size,              /* размер шифруемых данных */
      iv,                /* синхропосылка для режима гаммирования */
      sizeof( iv )       /* доступный размер синхропосылки */
    );
    timea = clock() - timea;
    if( error != ak_error_ok ) {
      aktool_error(_("computational error (%d)"), error );
      if( data ) free( data );
      goto exit;
    }

    if( aktool_test_verbose )
      printf(_(" %3uMB: 2 key encryption time: %fs, per 1MB = %fs, speed = %f MBs\n"), (unsigned int)i,
               (double) timea / (double) CLOCKS_PER_SEC,
               (double) timea / ( (double) CLOCKS_PER_SEC*i ),
               (double) CLOCKS_PER_SEC*i / (double) timea );
     else { printf("."); fflush( stdout ); }

    if( i > 16 ) {
      iter += 1;
      avg += (double) CLOCKS_PER_SEC*i / (double) timea;
    }
    free( data );
  }

  if( !aktool_test_verbose ) printf(_(" 128MB],"));
  printf(_(" average speed: %10f MBs\n"), avg/iter );

  exit_status = EXIT_SUCCESS;
  exit:
   ak_oid_delete_object( oid, encryptionKey );
   ak_oid_delete_second_object( oid, authenticationKey );

 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_speed_acpkm( ak_oid oid )
{
  clock_t timea;
  double iter = 0, avg = 0;
  size_t size = 0, secbytes = 0;
  ak_uint8 *data;
  int i, error = ak_error_ok, exit_status = EXIT_FAILURE;
  ak_pointer encryptionKey = NULL;

  printf(_("testing speed of %s (%s) algorithm\n"), oid->name[0], oid->id[0] );

 /* создаем ключи */
  if(( encryptionKey = ak_oid_new_object( oid )) == NULL ) {
    aktool_error( _("incorrect creation of encryption key (%d)" ), ak_error_get_value( ));
    goto exit;
  }

 /* приваиваем ключам значения */
  if(( error = ((ak_function_set_key_object *)oid->func.first.set_key)
                                                   ( encryptionKey, iv+16, 32 )) != ak_error_ok ) {
     aktool_error( _("incorrect assigning encryption key value (%d)" ), error );
     goto exit;
  }

 /* определяем максимальный размер секции */
  if( ((ak_bckey)encryptionKey)->bsize == 8 )
    secbytes = 8*ak_libakrypt_get_option_by_name( "acpkm_section_magma_block_count" );
   else secbytes = 16*ak_libakrypt_get_option_by_name( "acpkm_section_kuznechik_block_count" );
  printf(_("size of one section: %lu bytes\n"), (unsigned long int) secbytes );
  if( !aktool_test_verbose ) { printf(_("[16MB ")); fflush( stdout ); }

 /* теперь собственно тестирование скорости реализации */
  for( i = 16; i < 129; i += 8 ) {
    data = malloc( size = ( size_t ) i*1024*1024 );
    memset( data, (ak_uint8)i+13, size );

   /* на очень больших объемах одного ключа мало, надо увеличивать ресурс */
   /* далее - не очень хороший стиль, мы пользуемся тем,
      что все ключевые структуры содержат ключ первым элементом структуры */
    ((ak_skey)encryptionKey)->resource.value.counter = size;

    timea = clock();
    error = ( oid->func.direct )(
      encryptionKey,     /* ключ шифрования */
      data,              /* указатель на зашифровываемые данные */
      data,              /* указатель на зашифрованные данные */
      size,              /* размер шифруемых данных */
      secbytes,          /* размер одной секции в байтах */
      iv,                /* синхропосылка для режима гаммирования */
      sizeof( iv )       /* доступный размер синхропосылки */
    );
    timea = clock() - timea;
    if( error != ak_error_ok ) {
      aktool_error(_("computational error (%d)"), error );
      if( data ) free( data );
      goto exit;
    }

    if( aktool_test_verbose )
      printf(_(" %3uMB: acpkm time: %fs, per 1MB = %fs, speed = %f MBs\n"), (unsigned int)i,
               (double) timea / (double) CLOCKS_PER_SEC,
               (double) timea / ( (double) CLOCKS_PER_SEC*i ),
               (double) CLOCKS_PER_SEC*i / (double) timea );
     else { printf("."); fflush( stdout ); }

    if( i > 16 ) {
      iter += 1;
      avg += (double) CLOCKS_PER_SEC*i / (double) timea;
    }
    free( data );
  }

  if( !aktool_test_verbose ) printf(_(" 128MB],"));
  printf(_(" average speed: %10f MBs\n"), avg/iter );

  exit_status = EXIT_SUCCESS;
  exit:
   ak_oid_delete_object( oid, encryptionKey );

 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_speed_mac( ak_oid oid )
{
  clock_t timea;
  size_t size = 0;
  double iter = 0, avg = 0;
  ak_uint8 *data, icode[64];
  int i, error = ak_error_ok, exit_status = EXIT_FAILURE;
  ak_pointer encryptionKey = NULL;

  printf(_("testing speed of %s (%s) algorithm\n"), oid->name[0], oid->id[0] );

 /* создаем ключи */
  if(( encryptionKey = ak_oid_new_object( oid )) == NULL ) {
    aktool_error( _("incorrect creation of encryption key (%d)" ), ak_error_get_value( ));
    goto exit;
  }

 /* приваиваем ключам значения */
  if(( error = ((ak_function_set_key_object *)oid->func.first.set_key)
                                                   ( encryptionKey, iv+16, 32 )) != ak_error_ok ) {
     aktool_error( _("incorrect assigning encryption key value (%d)" ), error );
     goto exit;
  }
  if( !aktool_test_verbose ) { printf(_("[16MB ")); fflush( stdout ); }

 /* теперь собственно тестирование скорости реализации */
  for( i = 16; i < 129; i += 8 ) {
    data = malloc( size = ( size_t ) i*1024*1024 );
    memset( data, (ak_uint8)i+1, size );

   /* на очень больших объемах одного ключа мало, надо увеличивать ресурс */
   /* далее - не очень хороший стиль, мы пользуемся тем,
      что все ключевые структуры содержат ключ первым элементом структуры */
    ((ak_skey)encryptionKey)->resource.value.counter = size;

    timea = clock();
    error = ( oid->func.direct )(
      encryptionKey,     /* ключ шифрования */
      data,              /* указатель на данные для которых вычисляется имитовставка */
      size,              /* размер шифруемых данных */
      icode,             /* имитовставка */
      sizeof( icode )    /* доступный размер памяти для имитовставки */
    );
    timea = clock() - timea;
    if( error != ak_error_ok ) {
      aktool_error(_("computational error (%d)"), error );
      if( data ) free( data );
      goto exit;
    }

    if( aktool_test_verbose )
      printf(_(" %3uMB: mac time: %fs, per 1MB = %fs, speed = %f MBs\n"), (unsigned int)i,
               (double) timea / (double) CLOCKS_PER_SEC,
               (double) timea / ( (double) CLOCKS_PER_SEC*i ),
               (double) CLOCKS_PER_SEC*i / (double) timea );
     else { printf("."); fflush( stdout ); }

    if( i > 16 ) {
      iter += 1;
      avg += (double) CLOCKS_PER_SEC*i / (double) timea;
    }
    free( data );
  }

  if( !aktool_test_verbose ) printf(_(" 128MB],"));
  printf(_(" average speed: %10f MBs\n"), avg/iter );

  exit_status = EXIT_SUCCESS;
  exit:
   ak_oid_delete_object( oid, encryptionKey );

 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_speed_aead( ak_oid oid )
{
  clock_t timea;
  size_t size = 0;
  double iter = 0, avg = 0;
  ak_uint8 *data, icode[64];
  int i, error = ak_error_ok, exit_status = EXIT_FAILURE;
  ak_pointer encryptionKey = NULL, authenticationKey = NULL;

  printf(_("testing speed of %s (%s) algorithm\n"), oid->name[0], oid->id[0] );

 /* создаем ключи */
  if(( encryptionKey = ak_oid_new_object( oid )) == NULL ) {
    aktool_error( _("incorrect creation of encryption key (%d)" ), ak_error_get_value( ));
    goto exit;
  }
  if(( authenticationKey = ak_oid_new_second_object( oid )) == NULL ) {
    aktool_error( _("incorrect creation of authentication key (%d)" ), ak_error_get_value( ));
    goto exit;
  }

 /* приваиваем ключам значения */
  if(( error = ((ak_function_set_key_object *)oid->func.first.set_key)
                                                   ( encryptionKey, iv+16, 32 )) != ak_error_ok ) {
     aktool_error( _("incorrect assigning encryption key value (%d)" ), error );
     goto exit;
  }
  if(( error = ((ak_function_set_key_object *)oid->func.second.set_key)
                                                  ( authenticationKey, iv, 32 )) != ak_error_ok ) {
     aktool_error(_("incorrect assigning authentication key value (%d)" ), error );
     goto exit;
  }
  if( !aktool_test_verbose ) { printf(_("[16MB ")); fflush( stdout ); }

 /* теперь собственно тестирование скорости реализации */
  for( i = 16; i < 129; i += 8 ) {
    data = malloc( 128 + (size = ( size_t ) i*1024*1024 ));
    memset( data, (ak_uint8)i+1, 128 + size );

   /* на очень больших объемах одного ключа мало, надо увеличивать ресурс */
   /* далее - не очень хороший стиль, мы пользуемся тем,
      что все ключевые структуры содержат ключ первым элементом структуры */
    ((ak_skey)authenticationKey)->resource.value.counter = size;
    ((ak_skey)encryptionKey)->resource.value.counter = size;

    timea = clock();
    error =
    (( ak_function_aead *) oid->func.direct)(
      encryptionKey,     /* ключ шифрования */
      authenticationKey, /* ключ имитозащиты */
      data,              /* ассоциированные данные */
      128,               /* размер ассоциированных данных */
      data+128,          /* указатель на зашифровываемые данные */
      data+128,          /* указатель на зашифрованные данные */
      size,              /* размер шифруемых данных */
      iv,                /* синхропосылка для режима гаммирования */
      sizeof( iv ),      /* доступный размер синхропосылки */
      icode,             /* имитовставка */
      sizeof( icode )    /* доступный размер памяти для имитовставки */
    );
    timea = clock() - timea;
    if( error != ak_error_ok ) {
      aktool_error(_("computational error (%d)"), error );
      if( data ) free( data );
      goto exit;
    }

    if( aktool_test_verbose )
      printf(_(" %3uMB: aead time: %fs, per 1MB = %fs, speed = %f MBs\n"), (unsigned int)i,
               (double) timea / (double) CLOCKS_PER_SEC,
               (double) timea / ( (double) CLOCKS_PER_SEC*i ),
               (double) CLOCKS_PER_SEC*i / (double) timea );
     else { printf("."); fflush( stdout ); }

    if( i > 16 ) {
      iter += 1;
      avg += (double) CLOCKS_PER_SEC*i / (double) timea;
    }
    free( data );
  }

  if( !aktool_test_verbose ) printf(_(" 128MB],"));
  printf(_(" average speed: %10f MBs\n"), avg/iter );

  exit_status = EXIT_SUCCESS;
  exit:
   ak_oid_delete_object( oid, encryptionKey );
   ak_oid_delete_second_object( oid, authenticationKey );

 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_speed_block_cipher( ak_oid oid )
{
  clock_t timea;
  size_t size = 0;
  ak_oid soid = oid;
  double iter = 0, avg = 0;
  ak_uint8 *data;
  int i, error = ak_error_ok, exit_status = EXIT_FAILURE;
  ak_pointer encryptionKey = NULL;

  printf(_("testing speed of %s (%s) algorithm\n"), oid->name[0], oid->id[0] );

 /* создаем ключи */
  if(( encryptionKey = ak_oid_new_object( oid )) == NULL ) {
    aktool_error( _("incorrect creation of encryption key (%d)" ), ak_error_get_value( ));
    goto exit;
  }

 /* приваиваем ключам значения */
  if(( error = ((ak_function_set_key_object *)oid->func.first.set_key)
                                                   ( encryptionKey, iv+16, 32 )) != ak_error_ok ) {
     aktool_error( _("incorrect assigning encryption key value (%d)" ), error );
     goto exit;
  }
  if( !aktool_test_verbose ) { printf(_("[16MB ")); fflush( stdout ); }

 /* теперь собственно тестирование скорости реализации */
  for( i = 16; i < 129; i += 8 ) {
    data = malloc( size = ( size_t ) i*1024*1024 );
    memset( data, (ak_uint8)i+13, size );

   /* на очень больших объемах одного ключа мало, надо увеличивать ресурс */
   /* далее - не очень хороший стиль, мы пользуемся тем,
      что все ключевые структуры содержат ключ первым элементом структуры */
    ((ak_skey)encryptionKey)->resource.value.counter = size;

    timea = clock();
    error = ak_bckey_encrypt_ecb( encryptionKey, data, data, size );
    timea = clock() - timea;
    if( error != ak_error_ok ) {
      aktool_error(_("computational error (%d)"), error );
      if( data ) free( data );
      goto exit;
    }

    if( aktool_test_verbose )
      printf(_(" %3uMB: ecb time: %fs, per 1MB = %fs, speed = %f MBs\n"), (unsigned int)i,
               (double) timea / (double) CLOCKS_PER_SEC,
               (double) timea / ( (double) CLOCKS_PER_SEC*i ),
               (double) CLOCKS_PER_SEC*i / (double) timea );
     else { printf("."); fflush( stdout ); }

    if( i > 16 ) {
      iter += 1;
      avg += (double) CLOCKS_PER_SEC*i / (double) timea;
    }
    free( data );
  }

  if( !aktool_test_verbose ) printf(_(" 128MB],"));
  printf(_(" average speed: %10f MBs\n"), avg/iter );

  /* теперь запускаем все доступные алгоритмы тестирования */
  soid = oid;
  while( soid != NULL ){
     if( soid->mode != algorithm ) {
       if( strstr( soid->name[0], oid->name[0] ) != NULL ) {
           switch( soid->mode ) {
             case aead: exit_status = aktool_test_speed_aead( soid );
               break;
             case encryption: exit_status = aktool_test_speed_encryption( soid );
               break;
             case encryption2k: exit_status = aktool_test_speed_encryption2k( soid );
               break;
             case mac: exit_status = aktool_test_speed_mac( soid );
               break;
             case acpkm: exit_status = aktool_test_speed_acpkm( soid );
               break;
             default: break;
           }
       }
     }
     soid = ak_oid_findnext_by_engine( soid, block_cipher );
  }

  exit_status = EXIT_SUCCESS;
  exit:
   ak_oid_delete_object( oid, encryptionKey );

 return exit_status;

}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                  aktool_test.c  */
/* ----------------------------------------------------------------------------------------------- */
