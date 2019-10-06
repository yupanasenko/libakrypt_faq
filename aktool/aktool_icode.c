/* ----------------------------------------------------------------------------------------------- */
 #include <aktool.h>

/* ----------------------------------------------------------------------------------------------- */
 #ifdef LIBAKRYPT_HAVE_LIMITS_H
  #define _DEFAULT_SOURCE
  #include <limits.h>
 #endif

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_help( void );
 int aktool_icode_function( const char * , ak_pointer );
 int aktool_icode_check_function( char * , ak_pointer );

#if defined(_WIN32) || defined(_WIN64)
 char* strtok_r( char *, const char *, char ** );
#endif

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
   /*! \brief Флаг необходимости показа статистической информации при выводе результатов проверки */
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
   /*! Флаг совместимости с библиотекой openssl */
    bool_t openssl;
} ic;

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode( int argc, TCHAR *argv[] )
{
  int next_option = 0, idx = 0, exit_status = EXIT_FAILURE;
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
     { "openssl",             0, NULL,  247 },

    /* потом общие */
     { "audit",               1, NULL,   2  },
     { "help",                0, NULL,   1  },
     { NULL,                  0, NULL,   0  }
  };

 /* проверка наличия параметров */
  if( argc < 3 ) return aktool_icode_help();

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
  ic.openssl = ak_false;

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "a:c:t:o:rp", long_options, NULL );
       switch( next_option )
      {
       /* сначала обработка стандартных опций */
         case   1 : return aktool_icode_help();

         case   2 : /* получили от пользователя имя файла для вывода аудита */
                     aktool_set_audit( optarg );
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

         case 247 : /* установка флага совместимости */
                     ic.openssl = ak_true;
                     break;

         default:   /* обрабатываем ошибочные параметры */
                     if( next_option != -1 ) work = do_nothing;
                     break;
       }
  } while( next_option != -1 );
  if( work == do_nothing ) return aktool_icode_help();

 /* начинаем работу с криптографическими примитивами */
  if( ak_libakrypt_create( audit ) != ak_true ) {
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }

 /* теперь основная работа: выбираем заданное пользователем действие */
   switch( work )
  {
    case do_hash: /* вычисляем контрольную сумму */

     /* создаем дескриптор алгоритма итерационного сжатия */
      if(( ic.handle = ak_handle_new( ic.algorithm_ni, NULL )) == ak_error_wrong_handle ) {
        printf(_("\"%s\" is incorrect name/identifier for icode function\n"), ic.algorithm_ni );
        goto lab_exit;
      }
      if(( ak_handle_has_tag( ic.handle )) != ak_true ) {
        printf(_("algorithm \"%s\" cannot be used for integrity code calculations\n"),
                                                                              ic.algorithm_ni );
        goto lab_exit;
      }
      for( idx = 2; idx < argc; idx++ ) {
         switch( aktool_file_or_directory( argv[idx] ))
        {
          case DT_DIR: aktool_find( argv[idx], ic.template, aktool_icode_function, NULL, ic.tree );
            break;
          case DT_REG: aktool_icode_function( argv[idx] , NULL );
            break;
          default:    /* убираем из перебираемого списка параметры опций */
            if( strlen( argv[idx] ) && ( argv[idx][0] == '-' )) idx++;
            break;
         }
      }
      exit_status = EXIT_SUCCESS;
      break;

    case do_check: /* проверяем контрольную сумму */
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
 int aktool_icode_function( const char *filename, ak_pointer ptr )
{
  int error = ak_error_ok;
  char flongname[FILENAME_MAX];
  ak_uint8 out[127], ivector[31], outiv[64];

  ( void )ptr;
  memset( out, 0, sizeof( out ));
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
  if( ak_handle_get_tag_size( ic.handle ) > sizeof( out )) {
    if( ic.tag ) fprintf( ic.outfp, "%s (%s) = skipped\n", ic.algorithm_ni, filename );
      else fprintf( ic.outfp, "skipped %s\n", filename );
    return ak_error_message_fmt( error, __func__,
                                      "using mac algorithm with large integrity code size");
  }

 /* теперь начинаем процесс */
  if(( error = ak_handle_mac_file( ic.handle, filename, out, sizeof( out ))) != ak_error_ok ) {
    if( ic.tag ) fprintf( ic.outfp, "%s (%s) = skipped\n", ic.algorithm_ni, filename );
      else fprintf( ic.outfp, "skipped %s\n", filename );
    return ak_error_message_fmt( error, __func__,
                                        "incorrect evaluation mac for \"%s\" file", filename );
  }

 /* вывод результатов в следующих форматах
    linux:
      контрольная_сумма имя_файла
      контрольная_сумма имя_файла синхропосылка

    bsd:
      алгоритм (имя_файла) = контрольная_сумма
      алгоритм (имя_файла) = контрольная_сумма (синхропосылка) */

 /* теперь вывод результата */
  if( ic.tag ) { /* вывод bsd */
    fprintf( ic.outfp, "%s (%s) = %s\n", ic.algorithm_ni, filename,
                   ak_ptr_to_hexstr( out, ak_handle_get_tag_size( ic.handle ), ic.reverse_order ));

  } else { /* вывод линуксовый */
      fprintf( ic.outfp, "%s %s\n",
        ak_ptr_to_hexstr( out, ak_handle_get_tag_size( ic.handle ), ic.reverse_order ), filename );
    }
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_help( void )
{
  printf(_("aktool icode [options] [files or directories]  - calculate or checking integrity codes for given files\n\n"));
  printf(_("available options:\n"));
  printf(_(" -a, --algorithm <ni>    set the algorithm, where \"ni\" is name or identifier of mac or hash function\n" ));
  printf(_("                         default algorithm is \"streebog256\" defined by GOST R 34.10-2012\n" ));
  printf(_(" -c, --check <file>      check previously generated macs or integrity codes\n" ));
  printf(_("     --dont-show-stat    don't show a statistical results after checking\n"));
//  printf(_("     --hexkey <string>   set the key directly in command line as string of hexademals\n"));
  printf(_("     --ignore-errors     don't breake a check when file is missing or corrupted\n" ));
  printf(_("     --openssl-style     use key and data formats in openssl library style\n"));
  printf(_(" -o, --output <file>     set the output file for generated integrity codes\n" ));
  printf(_(" -p                      load the password from console to generate a secret key\n"));
  printf(_("     --password <pass>   set the password directly in command line\n"));
  printf(_("     --quiet             don't print OK for each successfully verified file\n"));
  printf(_(" -r, --recursive         recursive search of files\n" ));
  printf(_("     --reverse-order     output of integrity code in reverse byte order\n" ));
  printf(_("     --status            don't output anything, status code shows success\n" ));
  printf(_("     --tag               create a BSD-style checksum\n" ));
  printf(_(" -t, --template <str>    set the pattern which is used to find files\n"));

  printf(_("\ncommon aktool options:\n"));
  printf(_("     --audit <file>      set the output file for errors and libakrypt audit system messages\n" ));
  printf(_("     --help              show this information\n\n"));

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
#if defined(_WIN32) || defined(_WIN64)
 char* strtok_r( char *str, const char *delim, char **nextp)
{
 char *ret;

    if (str == NULL) { str = *nextp; }

    str += strspn(str, delim);
    if (*str == '\0') { return NULL; }

    ret = str;
    str += strcspn(str, delim);

    if (*str) { *str++ = '\0'; }

    *nextp = str;
    return ret;
}
#endif

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 aktool_icode.c  */
/* ----------------------------------------------------------------------------------------------- */
