/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 - 2021 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Прикладной модуль, реализующий процедуры тестирования функций библиотеки libakrypt             */
/*                                                                                                 */
/*  aktool_test.c                                                                                  */
/* ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <aktool.h>

/* ----------------------------------------------------------------------------------------------- */
/* - запуск теста криптографических алгоритмов
       aktool test --crypto --audit 2 --audit-file stderr                                          */
/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_help( void );
 int aktool_test_speed_mode( char * );
 int aktool_test_speed_name( char * );
 int aktool_test_speed_engine( char * );
 int aktool_test_speed_oid( int , ak_oid );

/* ----------------------------------------------------------------------------------------------- */
 bool_t large_array_test = ak_true;
 bool_t packets_test = ak_true;

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test( int argc, tchar *argv[] )
{
  char *value = NULL;
  int next_option = 0, exit_status = EXIT_SUCCESS;

  enum { do_nothing, do_dynamic, do_speed_engine,
             do_speed_name, do_speed_mode, do_list_modes, do_list_engines } work = do_nothing;

  const struct option long_options[] = {
     { "crypto",           0, NULL, 255 },
     { "speed-by-engine",  1, NULL, 'e' },
     { "speed-by-name",    1, NULL, 'n' },
     { "speed-by-mode",    1, NULL, 'm' },
     { "list-modes",       0, NULL, 254 },
     { "list-engines",     0, NULL, 253 },
     { "no-large-arrays",  0, NULL, 249 },
     { "no-packets",       0, NULL, 248 },

     aktool_common_functions_definition,
     { NULL,               0, NULL,   0 }
  };

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "he:n:m:", long_options, NULL );
       switch( next_option )
      {
        aktool_common_functions_run( aktool_test_help );

        case 255 : /* тест скорости функций хеширования */
                     work = do_dynamic;
                     break;

        case 'e': /* тест скорости для заданного типа криптографического алгоритма */
                     work = do_speed_engine; value = optarg;
                     break;
        case 'n': /* тест скорости по заданному фрагменту имени или идентификатора алгоритма */
                     work = do_speed_name; value = optarg;
                     break;
        case 'm': /* тест скорости по заданному режиму исопльзования алгоритма */
                     work = do_speed_mode; value = optarg;
                     break;
        case 254:    work = do_list_modes;
                     break;
        case 253:    work = do_list_engines;
                     break;

        case 249:    large_array_test = ak_false;
                     break;
        case 248:    packets_test = ak_false;
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
          aktool_error(_("complete crypto test is Wrong\n"));
          exit_status = EXIT_FAILURE;
        }
       break;

       case do_list_engines:
         printf(_("available engines: hash, hmac, cipher, sign\n"));
       break;

       case do_list_modes:
         printf(_("available modes: encrypt, encrypt2k, acpkm, mac, aead\n"));
       break;

       case do_speed_engine:
         exit_status = aktool_test_speed_engine( value );
         break;

       case do_speed_mode:
         exit_status = aktool_test_speed_mode( value );
         break;

       case do_speed_name:
         exit_status = aktool_test_speed_name( value );
         break;

     default:  break; /* конец switch( work ) */
   }

   if( exit_status == EXIT_FAILURE )
     if( !ki.quiet ) printf( _("for more information run test with \"--audit 2 --audit-file stderr\" options "
                                                                              "or see /var/log/auth.log file\n"));
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
     " -e, --speed-of-engine   measuring the speed of the all crypto algorithms defined by given engine\n"
     "     --list-engines      output a list of all supported engines\n"
     "     --list-modes        output a list of all supported modes\n"
     " -n, --speed-by-name     measuring the speed of the given crypto algorithm\n"
     "                         a search is performed for all algorithms whose name contains the specified string\n"
     "     --no-large-arrays   do not run tests with large arrays of pseudorandom data\n"
     "     --no-packets        do not run tests with short network packets\n"
     " -m, --speed-of-mode     mesuaring the speed of the crypto algorithms with given mode\n"
  ));
  aktool_print_common_options();

  printf(_("for usage examples try \"man aktool\"\n" ));
 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_speed_name( char *value )
{
 /* в этой фукнции поиск идентификаторов производится по имени или идентификатору,
    содержащему в своем составе заданный фрагмент */
  int returncode = EXIT_FAILURE, fc = 0;
  size_t idx, count = ak_libakrypt_oids_count() -1;
  for( idx = 0; idx < count; idx++ ) {
    int jdx;
    ak_oid oid = ak_oid_find_by_index( idx );
    if( oid == NULL ) return EXIT_FAILURE;

   /* поиск по идентификатору */
    jdx = 0;
    while( oid->id[jdx] != NULL ) {
      if( strstr( oid->id[jdx], value ) != NULL ) goto jump;
      ++jdx;
    }
   /* поиск по имени */
    jdx = 0;
    while( oid->name[jdx] != NULL ) {
      if( strstr( oid->name[jdx], value ) != NULL ) goto jump;
      ++jdx;
    }
    continue;
    jump:
      returncode = EXIT_SUCCESS;
      aktool_test_speed_oid( ++fc, oid );
  }
  if( returncode == EXIT_FAILURE ) {
    aktool_error(_("the string \"%s\" is not contained among the names or identifiers of the crypto algorithms"), value );
  }
 /* если ни чего не найдено, признак ошибки не возвращается */
  return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_speed_mode( char *value )
{

  return EXIT_FAILURE;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_speed_engine( char *value )
{

  return EXIT_FAILURE;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_speed_block_cipher( int, ak_oid );

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_speed_oid( int index, ak_oid oid )
{
  int exit_status = EXIT_SUCCESS;

  switch( oid->engine ) {
    case block_cipher:
      switch( oid->mode ) {
         case algorithm:
         case encrypt_mode:
         case encrypt2k_mode:
         case acpkm:
         case mac:
         case aead:
            exit_status = aktool_test_speed_block_cipher( index, oid );
            break;

         default:
           printf(_("%3d: block cipher %s, unsupported %s\n"), index, oid->name[0],
                                                          ak_libakrypt_get_mode_name( oid->mode ));
      }
      break;

    default:
      printf(_("identifier %s (%s) is unsupported\n"), oid->name[0], oid->id[0] );
  }

  return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 static ak_uint8 iv[48] = {
    0x12, 0x01, 0xf0, 0xe5, 0xd4, 0xc3, 0xb2, 0xa1, 0xf0, 0xce, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12,
    0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x90, 0x89, 0x78, 0x67, 0x56, 0x45, 0x34, 0x23,
    0xe9, 0xa8, 0x11, 0x12, 0x4c, 0x1b, 0x01, 0x1f, 0xf0, 0x87, 0xac, 0xab, 0x53, 0x19, 0x7d, 0xd1
  };

/* ----------------------------------------------------------------------------------------------- */
 const char *large  =  "   - large data encryption:";
 const char *packets = "   - packets encryption:";

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_speed_block_cipher( int index, ak_oid oid )
{
  clock_t timea = 1;
  double iter = 0, avg = 0;
  int i, j, error = ak_error_ok;
  size_t size = 0, sum = 0, isum = 0;
  int exit_status = EXIT_FAILURE;
  ak_pointer encryptionKey = NULL;
  const size_t pcount = 96000;
  ak_uint8 *packet, out[1500];

  size_t *lens = NULL;
 /* в режиме ecb все длины должны делиться на длину блока, т.е. 16 */
  size_t blens[12] = { 64, 128, 256, 384, 512, 640, 768, 832, 1024, 1040, 1280, 1488 };
 /* в остальных режимах допускаются произвольные размеры */
  size_t rlens[12] = { 64, 127, 128, 253, 460, 512, 731, 860, 1024, 1025, 1280, 1500 };

 /* 1. Создаем ключи */
  if(( encryptionKey = ak_oid_new_object( oid )) == NULL ) {
    aktool_error( _("incorrect creation of encryption key (code: %d)" ), ak_error_get_value( ));
    return exit_status;
  }
  if(( error = oid->func.first.set_key( encryptionKey, iv+16, 32 )) != ak_error_ok ) {
    aktool_error( _("incorrect assigning encryption key value (code: %d)" ), error );
    goto exit;
  }

 /* 1. выполняем тестирование больших данных */
  printf(_("%3d: block cipher %s, %s\n"), index, oid->name[0],
                    oid->mode == algorithm ? "ecb mode" : ak_libakrypt_get_mode_name( oid->mode ));
  if( large_array_test ) {
    for( i = 16; i < 129; i += 8 ) {
       ak_uint8 *data = malloc( size = ( size_t ) i*1024*1024 );
       memset( data, (ak_uint8)i+13, size );

     /* на очень больших объемах одного ключа мало, надо увеличивать ресурс */
     /* далее - не очень хороший стиль, мы пользуемся тем,
        что все ключевые структуры содержат ключ первым элементом структуры */
       ((ak_skey)encryptionKey)->resource.value.counter = size;

     /* выводим информацию */
       if( !ki.quiet ) { printf(_("%s %3d Mb%s"), _(large), i, "\r" ); fflush( stdout ); }

     /* выполняем алгоритм */
       switch( oid->mode ) {
          case algorithm:
            timea = clock();
            error = ak_bckey_encrypt_ecb( encryptionKey, data, data, size );
            timea = clock() - timea;
            break;

          default:
            printf(_("%3d: block cipher %s, %s\n"), index, oid->name[0],
                                                          ak_libakrypt_get_mode_name( oid->mode ));
       }
       if( error != ak_error_ok ) {
         aktool_error(_("computational error (%d)"), error );
         goto exit;
       }
       if( !ki.quiet ) {
         if( ki.verbose ) {
           printf(_("%s %3d Mb, time: %8f sec., per 1Mb: %f sec., average: %f MBs\n"),
            _(large),
            i,
            (double) timea / (double) CLOCKS_PER_SEC,
            (double) timea / ((double) CLOCKS_PER_SEC*i),
            (double) CLOCKS_PER_SEC*i / (double) timea );
         }
          else printf(_("%s %3d Mb, time: %8f sec.%s"),
                                     _(large), i, (double) timea / (double) CLOCKS_PER_SEC, "\r" );
       }

       iter += 1;
       avg += (double) CLOCKS_PER_SEC*i / (double) timea;
       free(data);
    }
    if( !ki.quiet )
      printf(_("   - average speed: %10f MBs\t\t\t\t\t\n"), avg/iter );
  }

// /* 2. выполняем тестирование пакетных данных */
//  if( packets_test ) {
//    sum = isum = 0;
//    packet = malloc( 1500*pcount );
//    for( i = 0; i < 1500*pcount; i++ ) packet[i] = (ak_uint8)i;

//    for( j = 0; j < 12; j++ ) {
//       printf("%s %s", _(packets), "\r" ); fflush( stdout );

//       ((ak_skey)encryptionKey)->resource.value.counter = pcount*1500;
//       size = 0;
//       timea = clock();
//       for( i = 0; i < pcount; i++, size += lens[j] ) {
//          ak_bckey_encrypt_ecb( encryptionKey, packet+size, out, lens[j] );
//       }
//       timea = clock() - timea;

//       double sec = (double) timea / (double) CLOCKS_PER_SEC;
//       size_t persec = (size_t) ((double)pcount / sec );

//       if( !ki.quiet ) {
//         if( ki.verbose )
//           printf("%s %4lu bytes, time: %f sec., packet per sec.: %lu\n",
//                                                               _(packets), lens[j], sec, persec );
//          else printf(_("%s %4lu bytes, time: %f sec., packet per sec.: %7lu%s"),
//                                                         _(packets), lens[j], sec, persec, "\r" );
//       }
//       sum += persec;
//       isum += ( lens[j]*persec );
//    }
//    free( packet );
//    if( !ki.quiet ) {
//      printf(_("   - average packets:                                                              \n"
//      "\t - %6lu per sec. (mean value)\n\t - %6lu per sec. (integral value)\n"),
//                                                                           sum/12, isum/(12*750 ));
//    }
//  }

  exit_status = EXIT_SUCCESS;
  exit:
   ak_oid_delete_object( oid, encryptionKey );

 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_speed_block_cipher_encrypt( ak_oid );

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_speed_block_cipher_encrypt2k( ak_oid );

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_speed_block_cipher_mac( ak_oid );

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_speed_block_cipher_aead( ak_oid );


/* ----------------------------------------------------------------------------------------------- */
/*                                                                                  aktool_test.c  */
/* ----------------------------------------------------------------------------------------------- */
