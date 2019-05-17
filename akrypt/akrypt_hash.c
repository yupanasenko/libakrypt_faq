#ifdef LIBAKRYPT_HAVE_LIMITS_H
 #define _DEFAULT_SOURCE
 #include <limits.h>
#endif
 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
 #include <akrypt.h>

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_hash_help( void );
 int akrypt_hash_function( const char * , ak_pointer );
 int akrypt_hash_check_function( char * , ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
 static struct hash_info {
    ak_handle handle; /*!< дескриптор алгоритма вычисления кода целостности */
    FILE *outfp; /*!< дескриптор файла для вывода результатов */
    char outfile[FILENAME_MAX]; /*!< имя файла для вывода результатов */
    size_t total;  /*!< общее количество обработанных файлов */
    size_t successed; /*!< количество корректных кодов */
    bool_t oreverse; /*!< флаг разворота выводимых результатов */
    bool_t tree; /*!< флаг рекурсивной обработки каталогов */
    bool_t ignore_missing;
    bool_t quiet;
    bool_t show_stat;
    ak_uint8 padding[4];
  } ic;

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_hash( int argc, TCHAR *argv[] )
{
  int next_option = 0, idx = 0;
  enum { do_nothing, do_hash, do_check } work = do_hash;
  char *algorithm_ni = "streebog256", *checkfile = NULL,
   #ifdef _WIN32
       *pattern = "*.*";
   #else
       *pattern = "*";
   #endif

  const struct option long_options[] = {
     { "help",             0, NULL,  'h' },
     { "audit",            1, NULL,  255 },
     { "algorithm",        1, NULL,  'a' },
     { "check",            1, NULL,  'c' },
     { "pattern",          1, NULL,  'p' },
     { "output",           1, NULL,  'o' },
     { "recursive",        0, NULL,  'r' },
     { "reverse-order",    0, NULL,  254 },
     { "ignore-missing",   0, NULL,  253 },
     { "quiet",            0, NULL,  252 },
     { "dont-show-stat",   0, NULL,  251 },
     { NULL,               0, NULL,   0  }
  };

/*
  рекурсия при установленной маске поиска  - работает, надо только использовать кавычки

  добавить параметры вывода результатов
  --tag  create a BSD-style checksum

  --status don't output anything, status code shows success
*/

 /* инициализируем переменную */
  memset( &ic, 0, sizeof( struct hash_info ));
  ic.outfp = stdout;
  ic.oreverse = ic.tree = ic.ignore_missing = ic.quiet = ak_false;
  ic.show_stat = ak_true;

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "ha:c:o:p:r", long_options, NULL );
       switch( next_option )
      {
         case 'h' : return akrypt_hash_help();
         case 255 : /* получили от пользователя имя файла для вывода аудита */
                     akrypt_set_audit( optarg );
                     break;

         case 254 : /* установить обратный порядок вывода байт */
                     ic.oreverse = ak_true;
                     break;

         case 253 : /* игонорировать сообщения об ошибках */
                     ic.ignore_missing = ak_true;
                     break;

         case 252 : /* гасить вывод Ок при проверке */
                     ic.quiet = ak_true;
                     break;

         case 251 : /* гасить вывод Ок при проверке */
                     ic.show_stat = ak_false;
                     break;

         case 'a' : /* устанавливаем алгоритм хеширования */
                     algorithm_ni = optarg;
                     break;

         case 'c' : /* проверяем вычисленные ранее значения кодов целостности */
                     checkfile = optarg;
                     work = do_check;
                     break;

         case 'o' : /* устанавливаем имя файла для вывода результатов */
                     if(( ic.outfp = fopen( optarg, "w" )) == NULL ) {
                       printf( _("audit file \"%s\" cannot be created\n"), optarg );
                       work = do_nothing;
                     } else {
                             #ifdef _WIN32
                              GetFullPathName( optarg, FILENAME_MAX, ic.outfile, NULL );
                             #else
                              realpath( optarg , ic.outfile );
                             #endif
                            }
                     break;

         case 'p' : /* устанавливаем дополнительную маску для поиска файлов */
                     pattern = optarg;
                     break;

         case 'r' : /* устанавливаем флаг рекурсивного обхода каталогов */
                    ic.tree = ak_true;
                    break;

         default:   /* обрабатываем ошибочные параметры */
                     if( next_option != -1 ) work = do_nothing;
                     break;
       }
   } while( next_option != -1 );
   if( work == do_nothing ) return EXIT_FAILURE;

 /* начинаем работу с криптографическими примитивами */
   if( ak_libakrypt_create( audit ) != ak_true ) return ak_libakrypt_destroy();

 /* создаем дескриптор алгоритма хеширования */
   if(( ic.handle = ak_hash_new_oid_ni( algorithm_ni, NULL )) == ak_error_wrong_handle ) {
     printf(_("\"%s\" is incorrect name/identifier for hash function\n"), algorithm_ni );
     goto lab_exit;
   }

 /* выбираем заданное пользователем действие */
   switch( work )
  {
    case do_hash: /* вычисляем контрольную сумму */
                   for( idx = 1; idx < argc; idx++ ) {
                       int type = akrypt_file_or_directory( argv[idx] );
                       switch( type )
                      {
                       case DT_DIR: akrypt_find( argv[idx], pattern, akrypt_hash_function, &ic, ic.tree );
                                    break;
                       case DT_REG: akrypt_hash_function( argv[idx] , &ic );
                                    break;
                       default:    /* убираем из перебираемого списка параметры опций */
                                    if( strlen( argv[idx] ) && ( argv[idx][0] == '-' )) idx++;
                           break;
                      }
                   }
                   break;

    case do_check: /* проверяем контрольную сумму */
                   ak_file_read_by_lines( checkfile, akrypt_hash_check_function, &ic );
                   if( ic.show_stat ) {
                     printf(_("\ntotal: %lu files, where: correct %lu, wrong %lu.\n\n"),
                               (unsigned long int)ic.total, (unsigned long int)ic.successed,
                                                   (unsigned long int)( ic.total - ic.successed ));
                   }
                   break;
    default:       break;
   }

 /* завершаем работу и выходим */
 lab_exit:
   if( ic.outfp != NULL ) fclose( ic.outfp );

 return ak_libakrypt_destroy();
}

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_hash_function( const char *filename, ak_pointer ptr )
{
  int error = ak_error_ok;
  struct hash_info *ic = ptr;
  char flongname[FILENAME_MAX];
  ak_uint8 out[akrypt_max_icode_size], outstr[2*akrypt_max_icode_size+2];

 /* файл для вывода результатов не хешируем */
  if( ic->outfp != NULL ) {
   #ifdef _WIN32
    GetFullPathName( filename, FILENAME_MAX, flongname, NULL );
   #else
    realpath( filename, flongname );
   #endif
    if( !strncmp( flongname, ic->outfile, FILENAME_MAX - 2 )) return ak_error_ok;
    if( !strncmp( flongname, audit_filename, 1022 )) return ak_error_ok;
  }

 /* теперь собственно хеширование */
  ak_error_set_value( ak_error_ok );
  ak_hash_file( ic->handle, filename, out );
  if(( error = ak_error_get_value( )) != ak_error_ok )
    ak_error_message_fmt( error, __func__,
                             "incorrect evaluation of integrity code for \"%s\" file", filename );
   else {
          ak_ptr_to_hexstr_static( out, ak_hash_get_size( ic->handle ),
                                                outstr, 2*akrypt_max_icode_size+2, ic->oreverse );
         /* это линуксовый вывод */
          fprintf( ic->outfp, "%s %s\n", outstr, filename );
        }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_hash_check_function( char *string, ak_pointer ptr )
{
  int error = ak_error_ok;
  size_t offset = 0, isize = 0;
  struct hash_info *ic = ptr;
  ak_uint8 preout[akrypt_max_icode_size], out[akrypt_max_icode_size];

 /* проверяем, что дескриптор задан корректно */
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                    "using null pointer to hash function handle" );
 /* проверяем, что строка достаточно длинная */
  isize = ak_hash_get_size( ic->handle );
  if(( offset = 2*isize) + 1 >= strlen( string ))
    return ak_error_message_fmt( ak_error_wrong_length, __func__ ,
                                                       "unexpected length of line: [%s]", string );
 /* увеличиваем счетчик обработанных файлов */
  ic->total++;

 /* получаем хеш из файла */
  string[offset] = 0;
  memset( preout, 0, akrypt_max_icode_size );
  ak_hexstr_to_ptr( string, preout, offset, ic->oreverse );
  offset++;

 /* вычисляем хеш и проверяем равенство */
  memset( out, 0, akrypt_max_icode_size );
  ak_error_set_value( ak_error_ok );
  ak_hash_file( ic->handle, string+offset, out );

  if(( error = ak_error_get_value()) != ak_error_ok ) {
    fprintf( ic->outfp, _("%s (wrong access to file, maybe file is missing)\n"), string+offset );
    ak_error_message_fmt( error, __func__ ,
                                   "wrong calculation of hash code for file %s", string+offset );
    if( ic->ignore_missing ) return ak_error_ok;
     else return  error;
  }

 /* сравниваем */
  fprintf( ic->outfp, "%s ", string+offset );
  if( ak_ptr_is_equal( out, preout, isize )) {
    ic->successed++;
    if( ic->quiet ) printf("\n");
      else fprintf( ic->outfp, "Ok\n" );
    return ak_error_ok;
  }

  fprintf( ic->outfp, _("(wrong check sum)\n"));
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_hash_help( void )
{
  printf(_("akrypt hash [options] [directories or files]  - calculation or checking integrity codes for given files\n\n"));
  printf(_("available options:\n"));
  printf(_(" -a, --algorithm <ni>    set the algorithm, where \"ni\" is name or identifier of hash function\n" ));
  printf(_("                         default algorithm is \"streebog256\" defined by GOST R 34.10-2012\n" ));
  printf(_("     --audit <file>      set the output file for errors and libakrypt audit system messages\n" ));
  printf(_(" -c, --check <file>      check previously generated integrity codes\n" ));
  printf(_("     --dont-show-stat    don't show a statistical results after checking\n"));
  printf(_("     --ignore-missing    don't breake a check when file is missing\n" ));
  printf(_(" -o, --output <file>     set the output file for generated integrity codes\n" ));
  printf(_(" -p, --pattern <str>     set the pattern which is used to find files\n" ));
  printf(_("     --quiet             don't print OK for each successfully verified file\n"));
  printf(_(" -r, --recursive         recursive search of files\n" ));
  printf(_("     --reverse-order     output of integrity code in reverse byte order\n" ));
  printf(_(" -h, --help              show this information\n\n" ));

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                  akrypt_hash.c  */
/* ----------------------------------------------------------------------------------------------- */
