 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <aktool.h>

/* ----------------------------------------------------------------------------------------------- */
/* - запуск теста криптографических алгоритмов
       aktool test --crypto --audit 2 --audit-file stderr                                             */
/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_help( void );
 int aktool_speed_test_hash( ak_oid );
 int aktool_speed_test_hmac( ak_oid );
 int aktool_speed_test_oid( ak_oid );

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test( int argc, tchar *argv[] )
{
  ak_oid oid = NULL;
  char *value = NULL;
  int next_option = 0, exit_status = EXIT_SUCCESS;
  enum { do_nothing, do_dynamic, do_speed_oid, do_speed_hash, do_speed_mac } work = do_nothing;

  const struct option long_options[] = {
     { "crypto",           0, NULL, 255 },
     { "speed",            1, NULL, 254 },
     { "speed-hash",       0, NULL, 253 },
     { "speed-mac",        0, NULL, 252 },

     { "openssl-style",    0, NULL,   5 },
     { "audit",            1, NULL,   4 },
     { "dont-use-colors",  0, NULL,   3 },
     { "audit-file",       1, NULL,   2 },
     { "help",             0, NULL,   1 },
     { NULL,               0, NULL,   0 }
  };

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "", long_options, NULL );
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

        case 255 : /* тест скорости функций хеширования */
                     work = do_dynamic;
                     break;

        case 254 : /* тест скорости по заданному идентификатору алгоритма */
                     work = do_speed_oid; value = optarg;
                     break;

        case 253 :   work = do_speed_hash; break;
        case 252 :   work = do_speed_mac; break;

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

     case do_speed_hash:
       oid = ak_oid_find_by_engine( hash_function );
       while( oid != NULL ) {
         if( oid->mode == algorithm )
          if(( exit_status = aktool_speed_test_hash( oid )) == EXIT_FAILURE ) break;
         oid = ak_oid_findnext_by_engine( oid, hash_function );
       }
       if( exit_status == EXIT_FAILURE ) printf(_("speed test for hash functions is Wrong\n"));
       break;

     case do_speed_mac:
       oid = ak_oid_find_by_mode( algorithm );
       while( oid != NULL ) {
         if( oid->engine == hmac_function )
          if(( exit_status = aktool_speed_test_hmac( oid )) == EXIT_FAILURE ) break;
         oid = ak_oid_findnext_by_mode( oid, algorithm );
       }
       if( exit_status == EXIT_FAILURE ) printf(_("speed test for mac functions is Wrong\n"));
       break;

     case do_speed_oid:
       oid = ak_oid_find_by_ni( value );
       if( oid == NULL ) {
         printf(_("using unsupported name or identifier \"%s\"\n\n"), value );
         printf(_("try \"aktool show --oids\" for list of all available identifiers\n"));
         exit_status = EXIT_FAILURE;
         break;
       }
       if( oid->mode != algorithm ) {
         printf(_("you must use name or identifier in \"algorithm\" mode (for %s mode is %s)\n\n"),
                                             oid->name[0], ak_libakrypt_get_mode_name( oid->mode ));
         printf(_("try \"aktool show --oid algorithm\" for list of all available algorithms\n"));
         exit_status = EXIT_FAILURE;
         break;
       }
       if( oid->engine == hash_function ) {
         exit_status = aktool_speed_test_hash( oid );
         break;
       }
       if( oid->engine == hmac_function ) {
         exit_status = aktool_speed_test_hmac( oid );
         break;
       }
       printf(_("this type of algorithms (%s) is not supported yet for testing, sorry ... \n"),
                                                       ak_libakrypt_get_engine_name( oid->engine ));
       exit_status = EXIT_SUCCESS;
       break;

     default:  break;
   }
   if( exit_status == EXIT_FAILURE )
     printf(_("for more information run test with \"--audit-file stderr\" option or see /var/log/auth.log file\n"));

 /* завершаем работу и выходим */
   aktool_destroy_libakrypt();

 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_speed_test_hash( ak_oid oid )
{
  clock_t timea;
  int i, error;
  struct hash ctx;
  ak_uint8 *data, out[64];
  size_t size = 0;
  double iter = 0, avg = 0;

  if( oid == NULL ) return EXIT_FAILURE;
  if( oid->engine != hash_function ) return EXIT_FAILURE;

  printf("speed test for: %s (%s)\n", oid->name[0], oid->id[0] );

/* статический объект существует, но он требует инициализации */
  if(( error = ak_hash_create_oid( &ctx, oid )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect initialization of hash context" );
    return EXIT_FAILURE;
  }

  for( i = 16; i < 129; i += 8 ) {
    data = malloc( size = ( size_t ) i*1024*1024 );
    memset( data, (ak_uint8)i+1, size );

   /* теперь собственно хеширование памяти */
    timea = clock();
    ak_mac_ptr( &ctx.mctx, data, size, out, sizeof( out ));
    timea = clock() - timea;
    printf(_(" %3uMB: hash time: %fs, per 1MB = %fs, speed = %f MBs\n"), (unsigned int)i,
               (double) timea / (double) CLOCKS_PER_SEC,
               (double) timea / ( (double) CLOCKS_PER_SEC*i ),
               (double) CLOCKS_PER_SEC*i / (double) timea );
    if( i > 16 ) {
      iter += 1;
      avg += (double) CLOCKS_PER_SEC*i / (double) timea;
    }
    free( data );
  }

  printf(_("average speed: %f MByte/sec\n\n"), avg/iter );
  ak_hash_destroy( &ctx );

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_speed_test_hmac( ak_oid oid )
{
  clock_t timea;
  int i, error;
  struct hmac ctx;
  ak_uint8 *data, out[64];
  size_t size = 0;
  double iter = 0, avg = 0;

  if( oid == NULL ) return EXIT_FAILURE;
  if( oid->engine != hmac_function ) return EXIT_FAILURE;

/* статический объект существует, но он требует инициализации */
  if(( error = ak_hmac_create_oid( &ctx, oid )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect initialization of hmac context" );
    return EXIT_FAILURE;
  }

  printf("speed test for %s (%s) mac algorithm with %u bits integrity code\n",
     oid->name[0], oid->id[0], (unsigned int)( ak_hmac_get_tag_size( &ctx ) << 3));

/* устанавливаем ключ, для теста скорости его значение не принципиально */
  if(( error = ak_hmac_set_key_random( &ctx, &ctx.key.generator )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect assigning of secret key" );
    ak_hmac_destroy( &ctx );
    return EXIT_FAILURE;
  }

  for( i = 16; i < 129; i += 8 ) {
    data = malloc( size = ( size_t ) i*1024*1024 );
    memset( data, (ak_uint8)i+1, size );

   /* теперь собственно хеширование памяти */
    timea = clock();
    ak_mac_ptr( &ctx.mctx, data, size, out, sizeof( out ));
    timea = clock() - timea;
    printf(_(" %3uMB: hmac time: %fs, per 1MB = %fs, speed = %f MBs\n"), (unsigned int)i,
               (double) timea / (double) CLOCKS_PER_SEC,
               (double) timea / ( (double) CLOCKS_PER_SEC*i ),
               (double) CLOCKS_PER_SEC*i / (double) timea );
    if( i > 16 ) {
      iter += 1;
      avg += (double) CLOCKS_PER_SEC*i / (double) timea;
    }
    free( data );
  }

  printf(_("average speed: %f MByte/sec\n\n"), avg/iter );
  ak_hmac_destroy( &ctx );

 return EXIT_SUCCESS;
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
     "     --speed-hash        speed test of all hash functions\n"
     "     --speed-mac         speed test of all message authentication functions\n"
     "\n"
     "for more information run tests with \"--audit-file stderr\" option or see /var/log/auth.log file\n"
  ));

 return aktool_print_common_options();
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                  aktool_test.c  */
/* ----------------------------------------------------------------------------------------------- */
