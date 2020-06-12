/* ----------------------------------------------------------------------------------------------- */
 #include <aktool.h>

/* ----------------------------------------------------------------------------------------------- */
 #ifdef LIBAKRYPT_HAVE_LIMITS_H
  #ifndef _DEFAULT_SOURCE
    #define _DEFAULT_SOURCE
  #endif
  #include <limits.h>
 #endif

/* ----------------------------------------------------------------------------------------------- */
 #ifndef _POSIX_C_SOURCE
   #define _POSIX_C_SOURCE
 #endif
 #include <string.h>

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_help( void );
 int aktool_icode_function( const char * , ak_pointer );
 int aktool_icode_check_function( char * , ak_pointer );
 bool_t aktool_create_handle( void );


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
    char password[aktool_max_password_len];
   /*! \brief Флаг выработки ключа из пароля */
    bool_t pass_flag;
   /*! \brief Флаг определения ключа в явном виде */
    bool_t hexkey_flag;
   /*! \brief Флаг определения ключа в виде имени файла */
    bool_t keyfile_flag;
   /*! \brief Указатель на строку с шестнадцатеричной записью ключа */
    char *hexstr;
   /*! \brief Указатель на строку с именем файла ключа */
    char *keyfile;
   /*! \brief Инициализационный вектор для алгоритма выработки ключа из пароля (константа) */
    ak_uint8 salt[32];
   /*! \brief Длина инициализационного вектора */
    size_t salt_len;
   /*! \brief Флаг рекурсивной обработки каталогов */
    bool_t tree;
   /*! Флаг совместимости с библиотекой openssl */
    bool_t openssl;
} ic;

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode( int argc, TCHAR *argv[] )
{
#ifdef _WIN32
  unsigned int cp = 0;
#endif
  int next_option = 0, exit_status = EXIT_FAILURE, error = ak_error_ok;
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
     { "hexkey",              1, NULL,  246 },
     { "salt",                1, NULL,  245 },
     { "salt-len",            1, NULL,  244 },
     { "key",                 1, NULL,  'k' },

    /* потом общие */
     { "dont-use-colors",     0, NULL,   3 },
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
  memset( ic.salt, 0, sizeof( ic.salt ));
  memcpy( ic.salt, "aKtool^_Qz;spe71oS--aG|q1#ck", 28 );
  ic.salt_len = sizeof( ic.salt ) >> 1;
  ic.hexkey_flag = ak_false;
  ic.keyfile_flag = ak_false;
  ic.hexstr = NULL;
  ic.keyfile = NULL;
  ic.openssl = ak_false;

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "a:c:t:o:k:rp", long_options, NULL );
       switch( next_option )
      {
       /* сначала обработка стандартных опций */
         case   1 : return aktool_icode_help();

         case   2 : /* получили от пользователя имя файла для вывода аудита */
                     aktool_set_audit( optarg );
                     break;
         case   3 : /* установка флага запрета вывода символов смены цветовой палитры */
                     ak_libakrypt_set_color_output( ak_false );

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
                       aktool_error(_("audit file \"%s\" cannot be created"), optarg );
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

         case 246:  /* определение ключа в явном виде */
                     ic.hexstr = optarg;
                     ic.hexkey_flag = ak_true;
                     break;

         case 245: /* установка salt */
                     memset( ic.salt, 0, sizeof( ic.salt ));
                     if( ak_hexstr_to_ptr( optarg, ic.salt, sizeof( ic.salt ),
                                                              ic.reverse_order ) != ak_error_ok ) {
                       aktool_error(_("salt consists of incorrect hexademal digits"));
                       goto lab_exit;
                     }
                     break;

         case 244: /* длина salt */
                     ic.salt_len =
                             ak_min( sizeof( ic.salt ), ak_max( 8, (unsigned int) atoi( optarg )));
                     break;

         case 'k':  /* определение имени файла с секретным ключом */
                     ic.keyfile = optarg;
                     ic.keyfile_flag = ak_true;
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

#ifdef _WIN32
  cp = GetConsoleCP();
  SetConsoleCP( 1251 );
  SetConsoleOutputCP( 1251 );
#endif

 /* теперь основная работа: выбираем заданное пользователем действие */
   switch( work )
  {
    case do_hash: /* вычисляем контрольную сумму */
      ++optind; /* пропускаем команду - i или icode */
      if( optind < argc ) {
       /* создаем дескриптор алгоритма */
        if( !aktool_create_handle( )) goto lab_exit;
       /* перебираем возможные значения */
        while( optind < argc ) {
           char *value = argv[optind++];

           switch( aktool_file_or_directory( value )) {
             case DT_DIR: aktool_find( value, ic.template, aktool_icode_function, NULL, ic.tree );
                break;
             case DT_REG: aktool_icode_function( value, NULL );
                break;
             default: aktool_error(_("%s is unsupported argument"), value );
                break;
           }
        }

    } else {
        exit_status = EXIT_FAILURE;
        aktool_error(_("no checksum arguments are defined"));
      }
    break;

//      do{
//        char *value = argv[--argc];
//        if( !strncmp( value, "i", 1 ) || !strncmp( value, "icode", 5 )) break;
//        printf("[%02d]: %s\n", argc, value );
//      }  while(1);

//      if( !aktool_create_handle( )) goto lab_exit;

//     /* перебираем все доступные параметры командной строки */
//      for( idx = 2; idx < argc; idx++ ) {
//         switch( aktool_file_or_directory( argv[idx] ))
//        {
//          case DT_DIR: aktool_find( argv[idx], ic.template, aktool_icode_function, NULL, ic.tree );
//            break;
//          case DT_REG: aktool_icode_function( argv[idx] , NULL );
//            break;

//          default:    /* убираем из перебираемого списка параметры опций */
//            if( strlen( argv[idx] ) && ( argv[idx][0] == '-' )) idx++;
//            break;
//        }
//      }
      exit_status = EXIT_SUCCESS;
      break;

    case do_check: /* проверяем контрольную сумму */
      if(( error = ak_file_read_by_lines( ic.checkfile, aktool_icode_check_function, NULL )) == ak_error_ok )
        exit_status = EXIT_SUCCESS;
      if( !ic.status ) {
        if( !ic.dont_stat_show ) {
          printf(_("\n%s [%lu lines, %lu files, where: correct %lu, wrong %lu]\n"),
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
  lab_exit:
   if( ic.outfp != NULL ) fclose( ic.outfp );
   ak_libakrypt_destroy();

#ifdef _WIN32
  SetConsoleCP( cp );
  SetConsoleOutputCP( cp );
#endif
 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t aktool_create_handle( void )
{
  int error = ak_error_ok;

 /* сначала пытаемся считать ключ из заданного файла */
  if( ic.keyfile_flag ) {
    struct oid_info oid;

   /* мы считываем и далее используем ключ того алгоритма,
      что указан в ключевом контейнере, а не в командой строке. */
    if(( ic.handle = ak_handle_new_from_file( ic.keyfile )) == ak_error_wrong_handle )
    {
      aktool_error(_("incorrect loading a secret key from file %s"), ic.keyfile );
      printf(_("try to rerun aktool with \"--audit stderr\" option\n"));
      return ak_false;
    }

    ak_handle_get_oid( ic.handle, &oid );
    ic.algorithm_ni = (char *)oid.names[0];
  }
   else {
    /* в альтернативной ветке создаем ключ с нуля:
       дескриптор алгоритма запрошенного пользователем алгоритма */
     if(( ic.handle = ak_handle_new( ic.algorithm_ni, NULL )) == ak_error_wrong_handle ) {
       aktool_error(_("\"%s\" is incorrect name/identifier for hash or mac function"),
                                                                                 ic.algorithm_ni );
       return ak_false;
     }
   }

 /* проверяем, что этот алгоритм позволяет реализовывать сжатие (хеширование или имитозащиту) */
  if(( ak_handle_check_icode( ic.handle )) != ak_true ) {
    aktool_error(_("algorithm %s cannot be used in integrity or authentity code calculation" ),
                                                                                 ic.algorithm_ni );
    return ak_false;
  }

 /* проверяем, что алгоритм допускает использование ключа */
  if( ak_handle_check_secret_key( ic.handle )) {

    if( ic.keyfile_flag ) goto lab_iv; /* уже все создано */
    if( ic.hexkey_flag ) {
       if(( error =
                ak_handle_set_key_from_hexstr( ic.handle, ic.hexstr, ak_false )) != ak_error_ok ) {
         aktool_error(_("incorrect key value %s"), ic.hexstr );
         return ak_false;
       }
     goto lab_iv;
    }

    if( ic.pass_flag ) {
     /* проверяем, установлен ли пароль */
      if( strlen( ic.password ) == 0 ) {
        printf(_("input password: "));
        error = ak_password_read( ic.password, sizeof( ic.password ));
        printf("\n");
        if( error != ak_error_ok ) return ak_false;
      } else { /* пароль уже установлен */ }

     /* теперь устанавливаем ключ, вырабатывая его из пароля */
      if(( error = ak_handle_set_key_from_password( ic.handle, ic.password,
                                  strlen( ic.password ), ic.salt, ic.salt_len )) != ak_error_ok ) {
        aktool_error(_("incorrect generation a secret key from password"));
        return ak_false;
      }
      goto lab_iv;
    }

    aktool_error(_("using %s algorithm without the specified key value"), ic.algorithm_ni );
    printf(_("try to define -p, --password, --key or --hexkey command line option\n"));
    return ak_false;
  }
   else {
     if( ic.keyfile_flag ) {
       aktool_error(_("%s algorithm does not use a secret key"), ic.algorithm_ni );
       return ak_false;
     }
   }

 /* проверяем, что алгоритм допускает использование синхропосылки */
  lab_iv:
 return ak_true;
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
 int aktool_icode_check_function( char *string, ak_pointer ptr )
{
  size_t len = 0;
  ak_uint8 out[64], out2[64];
  char *substr = NULL, *filename = NULL, *icode = NULL;
  int error = ak_error_ok, reterrror = ak_error_undefined_value;

 /* инициализируем значения локальных переменных */
  (void)ptr;
  ic.stat_lines++;
  if( ic.ignore_errors ) reterrror = ak_error_ok;

 /* получаем первый токен */
  if(( icode = strtok_r( string, "(", &substr )) == NULL ) return reterrror;
  if( strlen( substr ) == 0 ) { /* строка не содержит скобки => вариант строки в формате Linux */

   /* получаем первый токен - это должно быть значение контрольной суммы */
    if(( icode = strtok_r( string, " ", &substr )) == NULL ) return reterrror;
    if(( error = ak_hexstr_to_ptr( icode, out2, sizeof( out2 ), ic.reverse_order )) != ak_error_ok ) {
      return ak_error_message_fmt( ak_error_ok, __func__, "incorrect icode string %s\n", icode );
    }
   /* теперь второй токен - это имя файла */
    if(( filename = strtok_r( substr, " ", &substr )) == NULL ) return reterrror;

   /* если дескриптор не создан, то его нужно создать */
    if( ic.handle == ak_error_wrong_handle )
      if( !aktool_create_handle( )) return reterrror;

  } else { /* обнаружилась скобка => вариант строки в формате BSD */

   /* теперь надо проверить, что пролученное значение действительно является
      допустимым криптографическим алгоритмом */

   /* сперва уничтожаем пробелы в конце слова и получаем имя */
    if( strlen( icode ) > 1024 ) return reterrror;
    if(( len = strlen( icode ) - 1 ) == 0 ) return reterrror;
    while(( icode[len] == ' ' ) && ( len )) icode[len--] = 0;

   /* если дескриптор не создан, то его нужно создать */
    if( ic.handle == ak_error_wrong_handle ) {
      ic.algorithm_ni = icode; /* значение находится в стеке, поэтому оно не исчезает при вызове функции */
      if( !aktool_create_handle( )) return reterrror;
    }

   /* теперь второй токен - это имя файла */
    if(( filename = strtok_r( substr, ")", &substr )) == NULL ) return reterrror;

   /* теперь, контрольная сумма */
    while(( *substr == ' ' ) || ( *substr == '=' )) substr++;
    if(( error = ak_hexstr_to_ptr( substr, out2, sizeof( out2 ), ic.reverse_order )) != ak_error_ok ) {
      return ak_error_message_fmt( ak_error_ok, __func__, "incorrect icode string %s\n", icode );
    }
  }

 /* приступаем к проверке*/
  ic.stat_total++;

 /* проверяем контрольную сумму */
  if(( error = ak_handle_mac_file( ic.handle, filename, out, sizeof( out ))) != ak_error_ok ) {
    if( !ic.status ) printf("%s Wrong\n", filename );
    ak_error_message_fmt( reterrror, __func__,
                               "incorrect evaluation integrity code for \"%s\" file", filename );
  }
  if( ak_ptr_is_equal( out, out2, ak_handle_get_tag_size( ic.handle )) == ak_true ) {
    if( !ic.status ) {
      if( ic.quiet ) printf("%s\n", filename );
        else printf("%s Ok\n", filename );
    }
    ic.stat_successed++;
  } else
     if( !ic.status ) {
      if( ic.quiet ) aktool_error(_("%s"), filename );
       else aktool_error(_("%s Wrong"), filename );
     }
 return ak_error_ok;
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
  printf(_("     --hexkey <hex>      set the secret key directly in command line as a string of hexademal digits\n"));
  printf(_("     --ignore-errors     don't breake a check when file is missing or corrupted\n" ));
  printf(_(" -k  --key <file>        use the secret key from a specified file\n" ));
  printf(_("     --openssl-style     use data formats as in openssl library\n"));
  printf(_(" -o, --output <file>     set the output file for generated integrity codes\n" ));
  printf(_(" -p                      load the password from console to generate a secret key\n"));
  printf(_("     --password <pass>   set the password directly in command line\n"));
  printf(_("     --quiet             don't print OK for each successfully verified file\n"));
  printf(_(" -r, --recursive         recursive search of files\n" ));
  printf(_("     --reverse-order     output of integrity code in reverse byte order\n" ));
  printf(_("     --salt              set the initial value of PBKDF2 function for key generaton from password\n"));
  printf(_("     --salt-len <int>    change the length of salt buffer, in octets; default value is %u\n"),
                                                                           (unsigned int) sizeof( ic.salt ) >> 1 );
  printf(_("     --status            don't output anything, status code shows success\n" ));
  printf(_("     --tag               create a BSD-style checksum\n" ));
  printf(_(" -t, --template <str>    set the pattern which is used to find files\n"));

 return aktool_print_common_options();
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
