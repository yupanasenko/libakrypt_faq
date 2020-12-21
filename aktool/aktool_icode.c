/* ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <aktool.h>

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_help( void );
 int aktool_icode_function( const char * , ak_pointer );
 int aktool_icode_check_function( char * , ak_pointer );
 int aktool_create_handle( void );

/* ----------------------------------------------------------------------------------------------- */
#if defined(_WIN32) || defined(_WIN64)
 char* strtok_r( char *, const char *, char ** );
#endif

/* ----------------------------------------------------------------------------------------------- */
 static struct {
   /*! \brief Идентификатор используемого алгоритма */
    ak_oid algorithm;
   /*! \brief Шаблон для поиска файлов */
    char *template;
   /*! \brief Флаг рекурсивной обработки каталогов */
    bool_t tree;
   /*! \brief Контекст алгоритма сжатия */
    ak_pointer handle;
   /*! \brief Вывод результата в стиле BSD */
    bool_t tag;
   /*! \brief Флаг разворота выводимых/вводимых результатов */
    bool_t reverse_order;
  /*! \brief Дескриптор файла для вывода результатов */
    FILE *outfp;

  /*! \brief Имя файла для вывода результатов */
    char outfile[FILENAME_MAX];
 } ic;

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode( int argc, tchar *argv[] )
{
  int next_option = 0, exit_status = EXIT_FAILURE;
  enum { do_nothing, do_hash, do_check } work = do_hash;

  const struct option long_options[] = {
   /* сначала уникальные */
     { "algorithm",           1, NULL,  'a' },
     { "template",            1, NULL,  't' },
     { "output",              1, NULL,  'o' },
     { "recursive",           0, NULL,  'r' },
     { "reverse-order",       0, NULL,  254 },
     { "tag",                 0, NULL,  250 },

   /* это стандартые для всех программ опции */
     { "openssl-style",       0, NULL,   5  },
     { "audit",               1, NULL,   4  },
     { "dont-use-colors",     0, NULL,   3  },
     { "audit-file",          1, NULL,   2  },
     { "help",                0, NULL,   1  },
     { NULL,                  0, NULL,   0  },
  };

 /* устанавливаем значения по-умолчанию */
  memset( &ic, 0, sizeof( ic ));
  ic.algorithm = ak_oid_find_by_name( "streebog256" );
  ic.template =
  #ifdef _WIN32
   "*.*";
  #else
   "*";
  #endif
  ic.tree = ak_false;
  ic.handle = NULL;
  ic.reverse_order = ak_false;
  ic.tag = ak_false;
  ic.outfp = stdout;

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "a:t:ro:", long_options, NULL );
       switch( next_option )
      {
        case  1  :  return aktool_icode_help();
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

     /* устанавливаем имя криптографического алгоритма*/
        case 'a' : if(( ic.algorithm = ak_oid_find_by_ni( optarg )) == NULL ) {
                     aktool_error(
                        _("using unsupported name or identifier \"%s\" for crypto algorithm"),
                                                                                          optarg );
                     printf(
                     _("try \"aktool s --oid algorithm\" for list of all available algorithms\n"));
                     return EXIT_FAILURE;
                   }
                   if( ic.algorithm->mode != algorithm ) {
                     aktool_error(
                        _("the stirng %s is an identifier for %s and is not a crypto algorithm" ),
                                         optarg, ak_libakrypt_get_mode_name( ic.algorithm->mode ));
                     printf(
                     _("try \"aktool s --oid algorithm\" for list of all available algorithms\n"));
                     return EXIT_FAILURE;
                   }
                   break;

        case 'o' : /* устанавливаем имя файла для вывода результатов */
                 #ifdef _WIN32
                   GetFullPathName( optarg, FILENAME_MAX, ic.outfile, NULL );
                 #else
                   realpath( optarg , ic.outfile );
                 #endif
                   if(( ic.outfp = fopen( optarg, "w" )) == NULL ) {
                     aktool_error(_("checksum file \"%s\" cannot be created"), optarg );
                     return EXIT_FAILURE;
                   }
                   break;

        case 't' : /* устанавливаем дополнительную маску для поиска файлов */
                   ic.template = optarg;
                   break;
        case 'r' : /* устанавливаем флаг рекурсивного обхода каталогов */
                   ic.tree = ak_true;
                   break;

        case 254 : /* установить обратный порядок вывода байт */
                   ic.reverse_order = ak_true;
                   break;

        case 250 : /* вывод в стиле BSD */
                   ic.tag = ak_true;
                   break;

        default:  /* обрабатываем ошибочные параметры */
                   if( next_option != -1 ) work = do_nothing;
                   break;
       }

   } while( next_option != -1 );
   if( work == do_nothing ) return aktool_icode_help();

 /* начинаем работу с криптографическими примитивами */
   if( !aktool_create_libakrypt( )) return EXIT_FAILURE;

 /* теперь вызов соответствующей функции */
   switch( work ) {
     case do_hash:
       ++optind; /* пропускаем команду - i или icode */
       if( optind < argc ) {
         if(( exit_status = aktool_create_handle()) != EXIT_SUCCESS ) break;
         while( optind < argc ) {
            char *value = argv[optind++];
            switch( ak_file_or_directory( value )) {
              case DT_DIR: ak_file_find( value, ic.template, aktool_icode_function, NULL, ic.tree );
                break;
              case DT_REG: aktool_icode_function( value, NULL );
                break;
              default: aktool_error(_("%s is unsupported argument"), value );
                break;
            }
         }
       } else {
          exit_status = EXIT_FAILURE;
          aktool_error(_("file or directory are not specified as the last argument of the program"));
         }
       if( ic.algorithm != NULL ) ak_oid_delete_object( ic.algorithm, ic.handle );
       exit_status = EXIT_SUCCESS;
       break;

     case do_check:
       exit_status = EXIT_FAILURE;
       break;

     default:
       exit_status = EXIT_FAILURE;
   }

 /* завершаем работу и выходим */
   if( ic.outfp != stdout ) fclose( ic.outfp );
   aktool_destroy_libakrypt();
 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_create_handle( void )
{
  if( ic.algorithm == NULL ) {
    aktool_error(
          _("use -a (--algorithm) option and set the cryptographic algorithm name or identifier"));
    return EXIT_FAILURE;
  }

  if(( ic.handle = ak_oid_new_object( ic.algorithm )) == NULL ) {
    aktool_error(_("incorrect creation a handle of crypto algorithm"));
    return EXIT_FAILURE;
  }

 /* проверяем, надо ли устанавливать ключ
     если --key, то берем из заданного файла (в форме контейнера библиотеки)

     если --hexkey, то из командной строки берется ключ

     если -p, то используется пароль
     если --password, --hexpass (то пароль берется из командной строки)

     если hex-input, то ввод пароля проиводится в шестнадцатеричном виде

 */
  if( ic.algorithm->func.first.set_key != NULL ) {



  }

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_function( const char *filename, ak_pointer ptr )
{
  ak_uint8 out[64];
  size_t tagsize = 0;
  int error = ak_error_ok;
  char flongname[FILENAME_MAX];

 /* файл для вывода результатов не хешируем */
  if( ic.outfp != stdout ) {
    memset( flongname, 0, sizeof( flongname ));
   #ifdef _WIN32
    GetFullPathName( filename, FILENAME_MAX, flongname, NULL );
   #else
    realpath( filename, flongname );
   #endif
    if( !strncmp( flongname, ic.outfile, FILENAME_MAX -2 )) return ak_error_ok;
    if( !strncmp( flongname, audit_filename, sizeof( audit_filename ) -2 )) return ak_error_ok;
  }

 /* хешируем данные */
  if( ic.algorithm->func.first.set_key == NULL ) {
    ak_hash_file( ic.handle, filename, out, sizeof( out ));
    tagsize = ak_hash_get_tag_size( ic.handle );
  }
   else { /* вычисляем имитовставку */

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
    fprintf( ic.outfp, "%s (%s) = %s\n", ic.algorithm->name[0], filename,
                                               ak_ptr_to_hexstr( out, tagsize, ic.reverse_order ));
  } else { /* вывод линуксовый */
      fprintf( ic.outfp, "%s %s\n", ak_ptr_to_hexstr( out, tagsize, ic.reverse_order ), filename );
    }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_help( void )
{
  printf(
   _("aktool icode [options] [files or directories]  - calculate or checking integrity codes for given files\n\n"
     "available options:\n"
     " -a, --algorithm <ni>    set the algorithm, where \"ni\" is name or identifier of mac or hash function\n"
     "                         default algorithm is \"streebog256\" defined by GOST R 34.10-2012\n"
     " -o, --output <file>     set the output file for generated authentication or integrity code\n"
     " -r, --recursive         recursive search of files\n"
     "     --reverse-order     output of authentication or integrity code in reverse byte order\n"
     "     --tag               create a BSD-style checksum format\n"
     " -t, --template <str>    set the pattern which is used to find files\n\n"));

  printf(_("for usage examples try \"man aktool\"\n" ));

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
