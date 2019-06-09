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

/* ----------------------------------------------------------------------------------------------- */
 static struct icode_info {
  /*! \brief Дескриптор файла для вывода результатов */
    FILE *outfp;
  /*! \brief Имя используемого алгоритма */
    char *algorithm_ni;
  /*! \brief Имя файла, содержащего строки для проверки */
    char *checkfile;
  /*! \brief Шаблон для поиска файлов */
    char *template;
   /*! \brief Общее количество обработанных файлов */
    size_t stat_total;
   /*! \brief Количество корректных кодов */
    size_t stat_successed;
   /*! \brief Флаг необходимости показа статистической информации при выводе рещультатов проверки */
    bool_t dont_stat_show;
   /*! \brief Флаг разворота выводимых/вводимых результатов */
    bool_t reverse_order;
   /*! \brief не прекращать проверку, если файл отсутствует */
    bool_t ignore_missing;
   /*! \brief Не выводить Ok при успешной проверке */
    bool_t quiet;
   /*! \brief Вывод результата в стиле BSD */
    bool_t tag;
   /*! \brief Молчаливая проверка */
    bool_t status;
   /*! \brief Массив для хранения iv */
    ak_uint8 iv_pointer[32];
   /*! \brief Размер iv */
    ssize_t iv_length;
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
  bool_t result = ak_false;
  int next_option = 0, idx = 0,
      error = ak_error_ok, exit_status = EXIT_FAILURE;
  enum { do_nothing, do_hash, do_check } work = do_hash;
  char algorithmName[128], algorithmOID[128];
  oid_modes_t mode = undefined_mode;
  oid_engines_t engine = undefined_engine;

  const struct option long_options[] = {
   /* сначала уникальные */
     { "algorithm",           1, NULL,  'a' },
     { "check",               1, NULL,  'c' },
     { "template",            1, NULL,  't' },
     { "output",              1, NULL,  'o' },
     { "recursive",           0, NULL,  'r' },
     { "reverse-order",       0, NULL,  254 },
     { "ignore-missing",      0, NULL,  253 },
     { "quiet",               0, NULL,  252 },
     { "dont-show-stat",      0, NULL,  251 },
     { "tag",                 0, NULL,  250 },
     { "status",              0, NULL,  249 },
     { "password",            0, NULL,  'p' },
     { "iv",                  1, NULL,  248 },

    /* потом общие */
     { "audit",               1, NULL,   2  },
     { "help",                0, NULL,   1  },
     { NULL,                  0, NULL,   0  }
  };

 /* проверка наличия параметров */
  if( argc < 3 ) return akrypt_icode_help();

 /* инициализируем переменные */
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
  ic.stat_total = 0;
  ic.stat_successed = 0;
  ic.reverse_order = ak_false;
  ic.ignore_missing = ak_false;
  ic.quiet = ak_false;
  ic.tag = ak_false;
  ic.status = ak_false;
  memset( ic.outfile, 0, sizeof( ic.outfile ));
  memset( ic.password, 0, sizeof( ic.password ));
  ic.pass_flag = ak_false;
  memset( ic.iv_pointer, 0, sizeof( ic.iv_pointer ));
  ic.iv_length = 0;
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
                     ic.ignore_missing = ak_true;
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

         case 248 : /* явно заданное значение синхрополсылки */
                     ic.iv_length = ak_hexstr_size( optarg );
                     if(( ic.iv_length < 0 ) || (( size_t )ic.iv_length > sizeof( ic.iv_pointer ))) {
                       printf( _("initail vector has wrong length\n"));
                       return EXIT_FAILURE;
                     }
                     if( ak_hexstr_to_ptr( optarg,
                            ic.iv_pointer, sizeof( ic.iv_pointer ), ak_false ) != ak_error_ok ) {
                      printf( _("initail vector is not correct hexademal string\n"));
                      return EXIT_FAILURE;
                     }
                     break;

         default:   /* обрабатываем ошибочные параметры */
                     if( next_option != -1 ) work = do_nothing;
                     break;
       }
  } while( next_option != -1 );
  if( work == do_nothing ) return akrypt_icode_help();

 /* начинаем работу с криптографическими примитивами */
  if( ak_libakrypt_create( audit ) != ak_true ) return ak_libakrypt_destroy();

 /* проверяем корректность введенного имени алгоритма */
  for( idx = 0; ( size_t )idx < ak_libakrypt_oids_count(); idx++ ) {
     ak_libakrypt_get_oid_by_index( ( size_t )idx, &engine, &mode,
         algorithmName, sizeof( algorithmName ), algorithmOID, sizeof( algorithmOID ));
     if( strncmp( ic.algorithm_ni, algorithmName, strlen( ic.algorithm_ni )) == 0 ) {
       result = ak_true;
       break;
     }
  }
  if( !result ) {
    printf(_("\"%s\" is incorrect name/identifier for mac or hash function\n"), ic.algorithm_ni );
    goto lab_exit;
  }

 /* проверяем, нужен ли ключ */
  if(( engine == hmac_function ) || ( engine == mac_function ) ||
     ( engine == omac_function ) || ( engine == mgm_function )) {
    /* в настоящее время поддерживаются только ключи, выработанные из пароля */
    if( ic.pass_flag ) {
      printf("input password: ");
      error = ak_password_read( ic.password, sizeof( ic.password ));
      printf("\n");
      if( error != ak_error_ok ) goto lab_exit;
    } else {
         printf(_("algorithm \"%s\" needs a secret key\n"), ic.algorithm_ni );
         goto lab_exit;
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
      break;

    case do_check: /* проверяем контрольную сумму */
      break;

    default:
      break;
   }
   exit_status = EXIT_SUCCESS;

 /* корректно завершаем работу */
  lab_exit:
   if( ic.outfp != NULL ) fclose( ic.outfp );
   ak_libakrypt_destroy();
 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_icode_function( const char *filename, ak_pointer ptr )
{
  int error = ak_error_ok;
  char flongname[FILENAME_MAX];
  ak_handle handle = ak_error_wrong_handle;
  ak_uint8 out[255], outstr[512];

 /* увеличиваем количество обработанных файлов */
  ( void )ptr;
  ic.stat_total++;
  ak_error_set_value( ak_error_ok );

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

 /* создаем дескриптор алгоритма итерационного сжатия */
  if(( handle = ak_mac_new_oid( ic.algorithm_ni, NULL )) == ak_error_wrong_handle ) {
    printf(_("\"%s\" is incorrect name/identifier for mac or hash function\n"), ic.algorithm_ni );
    return ak_error_get_value();
  }

 /* проверяем, что алгоритм допускает использование ключа */
  if( ak_mac_is_key_settable( handle )) {
   /* в настоящее время поддерживаются только ключи, выработанные из пароля */
    if( ic.pass_flag ) {
      if(( error = ak_mac_set_key_from_password( handle, ic.password, strlen( ic.password ),
                                              ic.salt, sizeof( ic.salt ))) != ak_error_ok ) {
        printf(_("incorrect setting a secret key\n"));
        goto lab_exit;
      }
    } else { }
  }

 /* теперь начинаем процесс */
  ak_mac_file( handle, filename, out );
  if(( error = ak_error_get_value( )) != ak_error_ok ) {
    if( ic.tag ) fprintf( ic.outfp, "%s (%s) = skipped\n", ic.algorithm_ni, filename );
      else fprintf( ic.outfp, _("skipped %s\n"), filename );
    return ak_error_message_fmt( error, __func__,
                               "incorrect evaluation integrity code for \"%s\" file", filename );
  }

 /* вывод результатов в следующих форматах
    linux:
      контрольная_сумма имя_файла
      контрольная_сумма синхропосылка имя_файла

    bsd:
      алгоритм (имя_файла) = контрольная_сумма
      алгоритм (имя_файла) = контрольная_сумма (синхропосылка) */

  ak_ptr_to_hexstr_static( out, ak_mac_get_size( handle ),
                                                     outstr, sizeof( outstr ), ic.reverse_order );

  if( ic.tag ) { /* вывод bsd */
    fprintf( ic.outfp, "%s (%s) = %s\n", ic.algorithm_ni, filename, outstr );

  } else { /* вывод линуксовый */
      fprintf( ic.outfp, "%s %s\n", outstr, filename );
    }

  lab_exit:
   ak_handle_delete( handle );
 return error;
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
  printf(_("     --ignore-missing    don't breake a check when file is missing\n" ));
  printf(_("     --iv <hexstr>       initial value as hexademal string, which used in some mac algorithms,\n"));
  printf(_("                         if value is not defined it's choosen randomly\n"));
  printf(_(" -o, --output <file>     set the output file for generated integrity codes\n" ));
  printf(_(" -p  --password          use password to generate a secret key, which used in mac algorithms\n"));
  printf(_("     --quiet             don't print OK for each successfully verified file\n"));
  printf(_(" -r, --recursive         recursive search of files\n" ));
  printf(_("     --reverse-order     output of integrity code in reverse byte order\n" ));
  printf(_("     --status            don't output anything, status code shows success\n" ));
  printf(_("     --tag               create a BSD-style checksum\n" ));
  printf(_(" -t, --template <str>    set the pattern which is used to find files\n" ));

  printf(_("\ncommon options:\n"));
  printf(_("     --audit <file>      set the output file for errors and libakrypt audit system messages\n" ));
  printf(_("     --help              show this information\n\n" ));
//  printf(_("  --key ?

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                  akrypt_hash.c  */
/* ----------------------------------------------------------------------------------------------- */
