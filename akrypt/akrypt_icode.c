/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_LIMITS_H
 #define _DEFAULT_SOURCE
 #include <limits.h>
#endif
 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
 #include <akrypt.h>

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_icode_help( void );
 int akrypt_icode_function( const char * , ak_pointer );
 int akrypt_icode_check_function( char * , ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
 static struct icode_info {
    ak_handle handle;
  /*! \brief Дескриптор файла для вывода результатов */
    FILE *outfp;
  /*! \brief Имя используемого алгоритма */
    char *algorithm_ni;
  /*! \brief Имя файла, содержащего строки для проверки */
    char *checkfile;
  /*! \brief Шаблон для поиска файлов */
    char *template;
   /*! \brief Количество строк файла с контрольными суммами. */
    size_t stat_lines;
   /*! \brief Общее количество обработанных файлов */
    size_t stat_total;
   /*! \brief Количество корректных кодов */
    size_t stat_successed;
   /*! \brief Флаг необходимости показа статистической информации при выводе рещультатов проверки */
    bool_t dont_stat_show;
   /*! \brief Флаг разворота выводимых/вводимых результатов */
    bool_t reverse_order;
   /*! \brief не прекращать проверку, если файл отсутствует */
    bool_t ignore_errors;
   /*! \brief Не выводить Ok при успешной проверке */
    bool_t quiet;
   /*! \brief Вывод результата в стиле BSD */
    bool_t tag;
   /*! \brief Молчаливая проверка */
    bool_t status;
   /*! \brief Имя файла для вывода результатов */
    char outfile[FILENAME_MAX];
   /*! \brief Буффер для хранения пароля */
    char password[256];
   /*! \brief Флаг выработки ключа из пароля */
    bool_t pass_flag;
   /*! \brief Инициализационный вектор для алгоритма выработки ключа из пароля (константа) */
    ak_uint8 salt[12];
  /*! \brief Флаг рекурсивной обработки каталогов */
    bool_t tree;
    ak_uint8 padding[4];
} ic;

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_icode( int argc, TCHAR *argv[] )
{
  int next_option = 0, idx = 0,
      error = ak_error_ok, exit_status = EXIT_FAILURE;
  enum { do_nothing, do_hash, do_check } work = do_hash;

  const struct option long_options[] = {
   /* сначала уникальные */
     { "algorithm",           1, NULL,  'a' },
     { "check",               1, NULL,  'c' },
     { "template",            1, NULL,  't' },
     { "output",              1, NULL,  'o' },
     { "recursive",           0, NULL,  'r' },
     { "reverse-order",       0, NULL,  254 },
     { "ignore-errors",       0, NULL,  253 },
     { "quiet",               0, NULL,  252 },
     { "dont-show-stat",      0, NULL,  251 },
     { "tag",                 0, NULL,  250 },
     { "status",              0, NULL,  249 },
     { "password",            1, NULL,  248 },

    /* потом общие */
     { "audit",               1, NULL,   2  },
     { "help",                0, NULL,   1  },
     { NULL,                  0, NULL,   0  }
  };

 /* проверка наличия параметров */
  if( argc < 3 ) return akrypt_icode_help();

 /* инициализируем переменные */
  ic.handle = ak_error_wrong_handle;
  ic.outfp = stdout;
  ic.tree = ak_false;
  ic.algorithm_ni = "streebog256";
  ic.checkfile = NULL;
  ic.template =
  #ifdef _WIN32
   "*.*";
  #else
   "*";
  #endif
  ic.dont_stat_show = ak_false;
  ic.stat_lines = 0;
  ic.stat_total = 0;
  ic.stat_successed = 0;
  ic.reverse_order = ak_false;
  ic.ignore_errors = ak_false;
  ic.quiet = ak_false;
  ic.tag = ak_false;
  ic.status = ak_false;
  memset( ic.outfile, 0, sizeof( ic.outfile ));
  memset( ic.password, 0, sizeof( ic.password ));
  ic.pass_flag = ak_false;
  memcpy( ic.salt, "akrypt saltx", 12 );

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "a:c:t:o:rp", long_options, NULL );
       switch( next_option )
      {
       /* сначала обработка стандартных опций */
         case   1 : return akrypt_icode_help();

         case   2 : /* получили от пользователя имя файла для вывода аудита */
                     akrypt_set_audit( optarg );
                     break;

       /* теперь опции, уникальные для icode */
         case 'a' : /* устанавливаем алгоритм хеширования */
                     ic.algorithm_ni = optarg;
                     break;

         case 'c' : /* проверяем вычисленные ранее значения кодов целостности */
                     ic.checkfile = optarg;
                     work = do_check;
                     break;

         case 't' : /* устанавливаем дополнительную маску для поиска файлов */
                     ic.template = optarg;
                     break;

         case 'o' : /* устанавливаем имя файла для вывода результатов */
                     if(( ic.outfp = fopen( optarg, "w" )) == NULL ) {
                       printf( _("audit file \"%s\" cannot be created\n"), optarg );
                       return EXIT_FAILURE;
                     } else {
                             #ifdef _WIN32
                              GetFullPathName( optarg, FILENAME_MAX, ic.outfile, NULL );
                             #else
                              realpath( optarg , ic.outfile );
                             #endif
                            }
                     break;

         case 'r' : /* устанавливаем флаг рекурсивного обхода каталогов */
                     ic.tree = ak_true;
                     break;

         case 254 : /* установить обратный порядок вывода байт */
                     ic.reverse_order = ak_true;
                     break;

         case 253 : /* игонорировать сообщения об ошибках */
                     ic.ignore_errors = ak_true;
                     break;

         case 252 : /* гасить вывод Ок при проверке */
                     ic.quiet = ak_true;
                     break;

         case 251 : /* гасить вывод статистической информации при проверке */
                     ic.dont_stat_show = ak_true;
                     break;

         case 250 : /* вывод в стиле BSD */
                     ic.tag = ak_true;
                     break;

         case 249 : /* молчаливая работа */
                     ic.status = ak_true;
                     break;

         case 'p' : /* неоходимо ввести пароль */
                     ic.pass_flag = ak_true;
                     break;

         case 248 : /* передача пароля через коммандную строку */
                     memset( ic.password, 0, sizeof( ic.password ));
                     strncpy( ic.password, optarg, sizeof( ic.password ) -1 );
                     ic.pass_flag = ak_true;
                     break;

         default:   /* обрабатываем ошибочные параметры */
                     if( next_option != -1 ) work = do_nothing;
                     break;
       }
  } while( next_option != -1 );
  if( work == do_nothing ) return akrypt_icode_help();

 /* начинаем работу с криптографическими примитивами */
  if( ak_libakrypt_create( audit ) != ak_true ) return ak_libakrypt_destroy();

 /* создаем дескриптор алгоритма итерационного сжатия */
  if((ic.handle = ak_mac_new_oid( ic.algorithm_ni, NULL )) == ak_error_wrong_handle ) {
    printf(_("\"%s\" is incorrect name/identifier for mac or hash function\n"), ic.algorithm_ni );
    goto lab_exit;
  }

 /* проверяем, нужен ли ключ */
  if( ak_mac_is_key_settable( ic.handle )) {
    /* в настоящее время поддерживаются только ключи, выработанные из пароля */
    if( ic.pass_flag ) {
      if( strlen( ic.password ) == 0 ) {
        printf("input password: ");
        error = ak_password_read( ic.password, sizeof( ic.password ));
        printf("\n");
        if( error != ak_error_ok ) goto lab_prexit;
      } else { /* пароль уже установлен */ }

    } else {
           printf(_("algorithm \"%s\" needs a secret key\n"), ic.algorithm_ni );
           goto lab_prexit;
      }
  }

 /* теперь основная работа: выбираем заданное пользователем действие */
   switch( work )
  {
    case do_hash: /* вычисляем контрольную сумму */
      for( idx = 2; idx < argc; idx++ ) {
         switch( akrypt_file_or_directory( argv[idx] ))
        {
          case DT_DIR: akrypt_find( argv[idx], ic.template, akrypt_icode_function, NULL, ic.tree );
            break;
          case DT_REG: akrypt_icode_function( argv[idx] , NULL );
            break;
          default:    /* убираем из перебираемого списка параметры опций */
            if( strlen( argv[idx] ) && ( argv[idx][0] == '-' )) idx++;
            break;
         }
      }
      exit_status = EXIT_SUCCESS;
      break;

    case do_check: /* проверяем контрольную сумму */
      if(( error = ak_file_read_by_lines( ic.checkfile, akrypt_icode_check_function, NULL )) == ak_error_ok )
        exit_status = EXIT_SUCCESS;
      if( !ic.status ) {
        if( !ic.dont_stat_show ) {
          printf(_("\n%s [%lu lines, %lu files, where: correct %lu, wrong %lu]\n\n"),
                  ic.checkfile, (unsigned long int)ic.stat_lines,
                  (unsigned long int)ic.stat_total, (unsigned long int)ic.stat_successed,
                                         (unsigned long int)( ic.stat_total - ic.stat_successed ));
         }
       }
      if( ic.stat_total == ic.stat_successed ) exit_status = EXIT_SUCCESS;
       else exit_status = EXIT_FAILURE;
      break;

    default:
      break;
   }

 /* корректно завершаем работу */
  lab_prexit:
   ak_handle_delete( ic.handle );
  lab_exit:  
   if( ic.outfp != NULL ) fclose( ic.outfp );
   ak_libakrypt_destroy();
 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_icode_function( const char *filename, ak_pointer ptr )
{
  size_t ivlen = 0;
  bool_t ivf = ak_false;
  int error = ak_error_ok;
  char flongname[FILENAME_MAX];
  ak_uint8 out[127], outstr[256], ivector[31], outiv[64];

  ( void )ptr;
  memset( out, 0, sizeof( out ));
  memset( outstr, 0, sizeof( outstr ));
  memset( ivector, 0, sizeof( ivector ));
  memset( outiv, 0, sizeof( outiv ));
  ak_error_set_value( ak_error_ok );

 /* увеличиваем количество обработанных файлов */
  ic.stat_total++;

 /* файл для вывода результатов не хешируем */
  if( ic.outfp != NULL ) {
   #ifdef _WIN32
    GetFullPathName( filename, FILENAME_MAX, flongname, NULL );
   #else
    realpath( filename, flongname );
   #endif
    if( !strncmp( flongname, ic.outfile, FILENAME_MAX - 2 )) return ak_error_ok;
    if( !strncmp( flongname, audit_filename, 1022 )) return ak_error_ok;
  }

 /* проверяем длины */
  if( ak_mac_get_size( ic.handle ) > sizeof( out )) {
    if( ic.tag ) fprintf( ic.outfp, "%s (%s) = skipped\n", ic.algorithm_ni, filename );
      else fprintf( ic.outfp, "skipped %s\n", filename );
    return ak_error_message_fmt( error, __func__,
                                      "using mac algorithm with large integrity code size");
  }

 /* проверяем, что алгоритм допускает использование ключа */
  if( ak_mac_is_key_settable( ic.handle )) {
   /* в настоящее время поддерживаются только ключи, выработанные из пароля */
    if( ic.pass_flag ) {
      if(( error = ak_mac_set_key_from_password( ic.handle, ic.password,
                       strlen( ic.password ), ic.salt, sizeof( ic.salt ))) != ak_error_ok ) {
        printf(_("incorrect setting a secret key\n"));
        return ak_error_message( error, __func__, "incrorrect setting a secret key" );
      }
    } else { }
  }

 /* проверяем, что алгоритм допускает использование синхропосылки */
  if( ak_mac_is_iv_settable( ic.handle )) {
    ivlen = ak_mac_get_iv_size( ic.handle );
    if( ivlen > sizeof( out )) {
      if( ic.tag ) fprintf( ic.outfp, "%s (%s) = skipped\n", ic.algorithm_ni, filename );
        else fprintf( ic.outfp, "skipped %s\n", filename );
      return ak_error_message_fmt( error, __func__, "using mac algorithm with large iv size");
    }
   /* вырабатываем случайное iv */
   /*! \todo Надо сделать действительно случайный выбор начального значения. */
    memset( ivector, 0x1e, sizeof( ivector ));
    (( short int *)&ivector)[0] = ( short int )ic.stat_total;
    if(( error = ak_mac_set_iv( ic.handle, ivector, ivlen )) != ak_error_ok ) {
      if( ic.tag ) fprintf( ic.outfp, "%s (%s) = skipped\n", ic.algorithm_ni, filename );
        else fprintf( ic.outfp, "skipped %s\n", filename );
      return ak_error_message_fmt( error, __func__, "using setting initial value");
    }
   /* устанавливаем флаг */
    ivf = ak_true;
  }

 /* теперь начинаем процесс */
  ak_mac_file( ic.handle, filename, out );
  if(( error = ak_error_get_value( )) != ak_error_ok ) {
    if( ic.tag ) fprintf( ic.outfp, "%s (%s) = skipped\n", ic.algorithm_ni, filename );
      else fprintf( ic.outfp, "skipped %s\n", filename );
    return ak_error_message_fmt( error, __func__,
                               "incorrect evaluation integrity code for \"%s\" file", filename );
  }

 /* вывод результатов в следующих форматах
    linux:
      контрольная_сумма имя_файла
      контрольная_сумма имя_файла синхропосылка

    bsd:
      алгоритм (имя_файла) = контрольная_сумма
      алгоритм (имя_файла) = контрольная_сумма (синхропосылка) */

  if( ivf ) {
    if(( error = ak_ptr_to_hexstr_static( ivector, ivlen,
                                 outiv, sizeof( outiv ), ic.reverse_order )) != ak_error_ok ) {
      if( ic.tag ) fprintf( ic.outfp, "%s (%s) = skipped\n", ic.algorithm_ni, filename );
        else fprintf( ic.outfp, "skipped %s\n", filename );
      return ak_error_message( error, __func__, "incorrect convert random initial value" );
    }
  }

  if(( error = ak_ptr_to_hexstr_static( out, ak_mac_get_size( ic.handle ),
                                 outstr, sizeof( outstr ), ic.reverse_order )) != ak_error_ok ) {
    if( ic.tag ) {
      fprintf( ic.outfp, "%s (%s) = skipped\n", ic.algorithm_ni, filename );
    } else  {
       fprintf( ic.outfp, "skipped %s\n", filename );
      }
    return ak_error_message( error, __func__, "incorrect convert output value" );
  }

 /* теперь вывод результата */
  if( ic.tag ) { /* вывод bsd */
    if( ivf ) fprintf( ic.outfp, "%s (%s) = %s (%s)\n", ic.algorithm_ni, filename, outstr, outiv );
      else fprintf( ic.outfp, "%s (%s) = %s\n", ic.algorithm_ni, filename, outstr );

  } else { /* вывод линуксовый */
      if( ivf ) fprintf( ic.outfp, "%s %s %s\n", outstr, filename, outiv );
       else fprintf( ic.outfp, "%s %s\n", outstr, filename );
    }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_icode_check_function( char *string, ak_pointer ptr )
{
  size_t ivlen = 0;
  int error = ak_error_ok;
  int reterrror = ak_error_undefined_value;
  ak_uint8 out[64], out2[64], outiv[32];
  char *token = NULL, *substr = NULL, *filename = NULL, *icode = NULL, *ivec = NULL;

 /* инициализируем значения локальных переменных */
  (void)ptr;
  ic.stat_lines++;
  if( ic.ignore_errors ) reterrror = ak_error_ok;

 /* получаем первый токен */
  if(( icode = strtok_r( string, " ", &substr )) == NULL ) return reterrror;

 /*  у нас есть имя алгоритма => проверяем */
  if( strncmp( icode, ic.algorithm_ni, strlen( ic.algorithm_ni )) == 0 ) {
   /* первый токен совпал с именем алгоритма => разбираем BSD вывод */
    filename = strtok_r( substr, " ", &substr );
    if( strlen(filename) < 3 ) return reterrror;
    filename[ strlen(filename) -1 ] = 0;
    filename++;

    if(( token = strtok_r( substr, " ", &substr )) == NULL ) return reterrror;
    if(( icode = strtok_r( substr, " ", &substr )) == NULL ) return reterrror;
    if(( error = ak_hexstr_to_ptr( icode, out2, sizeof( out2 ), ic.reverse_order )) != ak_error_ok ) {
      return ak_error_message_fmt( ak_error_ok, __func__, "incorrect icode string %s\n", icode );
    }

    if(( ivec = strtok_r( substr, " ", &substr )) != NULL ) {
      if( strlen(ivec) < 3 ) ivec = NULL;
       else {
        ivec[ strlen(ivec) -1 ] = 0;
        ivec++;
      }
      if(( error = ak_hexstr_to_ptr( ivec, outiv, sizeof( outiv ), ic.reverse_order )) != ak_error_ok )
        ivec = NULL;
    }
  } else {
   /* предполагаем, что вывод linux */
    if(( error = ak_hexstr_to_ptr( icode, out2, sizeof( out2 ), ic.reverse_order )) != ak_error_ok ) {
      return ak_error_message_fmt( ak_error_ok, __func__, "incorrect icode string %s\n", icode );
    }

    if(( filename = strtok_r( substr, " ", &substr )) == NULL ) return reterrror;

    if(( ivec = strtok_r( substr, " ", &substr )) != NULL ) {
      if(( error = ak_hexstr_to_ptr( ivec, outiv, sizeof( outiv ), ic.reverse_order )) != ak_error_ok )
        ivec = NULL;
    }
  }

 /* приступаем к проверке*/
  ic.stat_total++;

 /* проверяем, что алгоритм допускает использование ключа */
  if( ak_mac_is_key_settable( ic.handle )) {
   /* в настоящее время поддерживаются только ключи, выработанные из пароля */
    if( ic.pass_flag ) {
      if(( error = ak_mac_set_key_from_password( ic.handle, ic.password,
                       strlen( ic.password ), ic.salt, sizeof( ic.salt ))) != ak_error_ok ) {
        return ak_error_message( reterrror, __func__, "incrorrect setting a secret key" );
      }
    } else
       return ak_error_message( reterrror, __func__, "not defined password for key generation" );
  }

 /* проверяем, что алгоритм допускает использование синхропосылки */
  if( ak_mac_is_iv_settable( ic.handle )) {
    if( ivec == NULL ) return ak_error_message( reterrror, __func__,
                                                           "not defined value of initial vector" );
    ivlen = ak_mac_get_iv_size( ic.handle );
    if( 2*ivlen != strlen( ivec )) return ak_error_message( reterrror, __func__,
                                                            "incorrect length of initial vector" );
    if( ak_mac_set_iv( ic.handle, outiv, ivlen ) != ak_error_ok )
      return ak_error_message( reterrror, __func__, "incorrect setting of initial vector" );
  }

  ak_mac_file( ic.handle, filename, out );
  if(( error = ak_error_get_value( )) != ak_error_ok ) {
    if( !ic.status ) printf("%s Wrong\n", filename );
    ak_error_message_fmt( reterrror, __func__,
                               "incorrect evaluation integrity code for \"%s\" file", filename );
  }
  if( ak_ptr_is_equal( out, out2, ak_mac_get_size( ic.handle )) == ak_true ) {
    if( !ic.status ) {
      if( ic.quiet ) printf("%s\n", filename );
        else printf("%s Ok\n", filename );
    }
    ic.stat_successed++;
  } else
     if( !ic.status ) printf("%s Wrong\n", filename );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_icode_help( void )
{
  printf(_("akrypt icode [options] [files or directories]  - calculation and/or checking integrity codes for given files\n\n"));
  printf(_("available options:\n"));
  printf(_(" -a, --algorithm <ni>    set the algorithm, where \"ni\" is name or identifier of mac or hash function\n" ));
  printf(_("                         default algorithm is \"streebog256\" defined by GOST R 34.10-2012\n" ));
  printf(_(" -c, --check <file>      check previously generated macs or integrity codes\n" ));
  printf(_("     --dont-show-stat    don't show a statistical results after checking\n"));
  printf(_("     --ignore-errors     don't breake a check when file is missing or corrupted\n" ));
  printf(_(" -o, --output <file>     set the output file for generated integrity codes\n" ));
  printf(_(" -p                      load the password from console to generate a secret key\n"));
  printf(_("     --password <pass>   set the password directly in command line\n"));
  printf(_("     --quiet             don't print OK for each successfully verified file\n"));
  printf(_(" -r, --recursive         recursive search of files\n" ));
  printf(_("     --reverse-order     output of integrity code in reverse byte order\n" ));
  printf(_("     --status            don't output anything, status code shows success\n" ));
  printf(_("     --tag               create a BSD-style checksum\n" ));
  printf(_(" -t, --template <str>    set the pattern which is used to find files\n" ));

  printf(_("\ncommon akrypt options:\n"));
  printf(_("     --audit <file>      set the output file for errors and libakrypt audit system messages\n" ));
  printf(_("     --help              show this information\n\n" ));

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                  akrypt_hash.c  */
/* ----------------------------------------------------------------------------------------------- */
