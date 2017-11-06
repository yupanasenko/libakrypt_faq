/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2014 - 2017 by Axel Kenzo, axelkenzo@mail.ru                                    */
/*   All rights reserved.                                                                          */
/*                                                                                                 */
/*  Разрешается повторное распространение и использование как в виде исходного кода, так и         */
/*  в двоичной форме, с изменениями или без, при соблюдении следующих условий:                     */
/*                                                                                                 */
/*   1. При повторном распространении исходного кода должно оставаться указанное выше уведомление  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий.                   */
/*   2. При повторном распространении двоичного кода должна сохраняться указанная выше информация  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий в документации     */
/*      и/или в других материалах, поставляемых при распространении.                               */
/*   3. Ни имя владельца авторских прав, ни имена его соратников не могут быть использованы в      */
/*      качестве рекламы или средства продвижения продуктов, основанных на этом ПО без             */
/*      предварительного письменного разрешения.                                                   */
/*                                                                                                 */
/*  ЭТА ПРОГРАММА ПРЕДОСТАВЛЕНА ВЛАДЕЛЬЦАМИ АВТОРСКИХ ПРАВ И/ИЛИ ДРУГИМИ СТОРОНАМИ "КАК ОНА ЕСТЬ"  */
/*  БЕЗ КАКОГО-ЛИБО ВИДА ГАРАНТИЙ, ВЫРАЖЕННЫХ ЯВНО ИЛИ ПОДРАЗУМЕВАЕМЫХ, ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ИМИ, ПОДРАЗУМЕВАЕМЫЕ ГАРАНТИИ КОММЕРЧЕСКОЙ ЦЕННОСТИ И ПРИГОДНОСТИ ДЛЯ КОНКРЕТНОЙ */
/*  ЦЕЛИ. НИ В КОЕМ СЛУЧАЕ НИ ОДИН ВЛАДЕЛЕЦ АВТОРСКИХ ПРАВ И НИ ОДНО ДРУГОЕ ЛИЦО, КОТОРОЕ МОЖЕТ    */
/*  ИЗМЕНЯТЬ И/ИЛИ ПОВТОРНО РАСПРОСТРАНЯТЬ ПРОГРАММУ, КАК БЫЛО СКАЗАНО ВЫШЕ, НЕ НЕСЁТ              */
/*  ОТВЕТСТВЕННОСТИ, ВКЛЮЧАЯ ЛЮБЫЕ ОБЩИЕ, СЛУЧАЙНЫЕ, СПЕЦИАЛЬНЫЕ ИЛИ ПОСЛЕДОВАВШИЕ УБЫТКИ,         */
/*  ВСЛЕДСТВИЕ ИСПОЛЬЗОВАНИЯ ИЛИ НЕВОЗМОЖНОСТИ ИСПОЛЬЗОВАНИЯ ПРОГРАММЫ (ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ПОТЕРЕЙ ДАННЫХ, ИЛИ ДАННЫМИ, СТАВШИМИ НЕПРАВИЛЬНЫМИ, ИЛИ ПОТЕРЯМИ ПРИНЕСЕННЫМИ   */
/*  ИЗ-ЗА ВАС ИЛИ ТРЕТЬИХ ЛИЦ, ИЛИ ОТКАЗОМ ПРОГРАММЫ РАБОТАТЬ СОВМЕСТНО С ДРУГИМИ ПРОГРАММАМИ),    */
/*  ДАЖЕ ЕСЛИ ТАКОЙ ВЛАДЕЛЕЦ ИЛИ ДРУГОЕ ЛИЦО БЫЛИ ИЗВЕЩЕНЫ О ВОЗМОЖНОСТИ ТАКИХ УБЫТКОВ.            */
/*                                                                                                 */
/*   akrypt_icode.c                                                                                 */
/* ----------------------------------------------------------------------------------------------- */
#define _DEFAULT_SOURCE

 #include <limits.h>
 #include <stdlib.h>
 #include <string.h>
 #include <akrypt.h>

/* ----------------------------------------------------------------------------------------------- */
 #define akrypt_max_icode_size     (64)

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_icode_help( void );
 int akrypt_icode_function( const char *, ak_pointer );
 int akrypt_icode_check_function( char *string, ak_pointer ptr );

/* ----------------------------------------------------------------------------------------------- */
 struct icode_info {
  ak_handle handle; /* дескриптор алгоритма вычисления кода целостности */
  FILE *outfp; /* дескриптор файла для вывода результатов */
  char outfile[FILENAME_MAX]; /* имя файла для вывода результатов */
  size_t total;  /* общее количество обработанных файлов */
  size_t successed; /* количество корректных кодов */
 };

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_icode( int argc, char *argv[] )
{
  int next_option = 0, idx = 0;
  enum { do_nothing, do_icode, do_check } work = do_icode;
  ak_handle ohandle = ak_error_wrong_handle;
  char *algorithm_ni = "streebog256", *pattern = "*", *checkfile = NULL;
  ak_bool tree = ak_false; /* флаг рекурсивной обработки файлов */
  struct icode_info ic;

  const struct option long_options[] = {
     { "help",             0, NULL,  'h' },
     { "audit",            1, NULL,  255 },
     { "algorithm",        1, NULL,  'a' },
     { "check",            1, NULL,  'c' },
     { "pattern",          1, NULL,  'p' },
     { "output",           1, NULL,  'o' },
     { "recursive",        0, NULL,  'r' },
     { NULL,               0, NULL,   0  }
  };

 /* инициализируем переменную */
  memset( &ic, 0, sizeof( struct icode_info ));
  ic.outfp = stdout;

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "ha:c:o:p:r", long_options, NULL );
       switch( next_option )
      {
         case 'h' : return akrypt_icode_help();
         case 255 : /* получили от пользователя имя файла для вывода аудита */
                     akrypt_set_audit( optarg );
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
                       printf("file %s cannot be created\n", optarg );
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
                    tree = ak_true;
                    break;

         default:   /* обрабатываем ошибочные параметры */
                     if( next_option != -1 ) work = do_nothing;
                     break;
       }
   } while( next_option != -1 );
   if( work == do_nothing ) return EXIT_FAILURE;

 /* начинаем работу с криптографическими примитивами */
   if( ak_libakrypt_create( audit ) != ak_true ) return ak_libakrypt_destroy();

 /* проверяем заданный пользователем алгоритм*/
   if(( ohandle = ak_oid_find_by_name( algorithm_ni )) == ak_error_wrong_handle ) {
      if(( ohandle = ak_oid_find_by_id( algorithm_ni )) == ak_error_wrong_handle ) {
        printf("string \"%s\" is not valid name or identifier of icode function\n", algorithm_ni );
        goto lab_exit;
      }
   }
 /* создаем дескриптор алгоритма (пока только хеширования) */
   if(( ic.handle = ak_hash_new_oid( ohandle )) == ak_error_wrong_handle ) {
     printf("incorrect descriptor of \"%s\" icode function\n", algorithm_ni );
     goto lab_exit;
   }

   if( ak_hash_get_icode_size( ic.handle ) > akrypt_max_icode_size ) {
     printf("using algorithm with very large integrity code size\n");
     goto lab_exit;
   }

 /* выбираем заданное пользователем действие */
   switch( work )
  {
    case do_icode: /* вычисляем контрольную сумму */
                   for( idx = 1; idx < argc; idx++ ) {
                       int type = akrypt_file_or_directory( argv[idx] );
                       switch( type )
                      {
                       case DT_DIR: akrypt_find( argv[idx], pattern, akrypt_icode_function, &ic, tree );
                                    break;
                       case DT_REG: akrypt_icode_function( argv[idx] , &ic );
                                    break;
                       default:    /* убираем из перебираемого списка параметры опций */
                                    if( strlen( argv[idx] ) && ( argv[idx][0] == '-' )) idx++;
                           break;
                      }
                   }
                   break;

                   break;
    case do_check: /* проверяем контрольную сумму */
                   ak_file_read_by_lines( checkfile, akrypt_icode_check_function, &ic );
                   printf("\ntotal: %lu files, where correct: %lu, wrong: %lu.\n\n",
                               (unsigned long int)ic.total, (unsigned long int)ic.successed,
                                                   (unsigned long int)( ic.total - ic.successed ));
                   break;
    default: break;
   }

 /* завершаем работу и выходим */
 lab_exit:
   if( ic.outfp != NULL ) fclose( ic.outfp );

 return ak_libakrypt_destroy();
}

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_icode_function( const char *filename, ak_pointer ptr )
{
 /* этот код для hmac работать не будет */
  int error = ak_error_ok;
  struct icode_info *ic = ptr;
  ak_uint8 out[akrypt_max_icode_size], outstr[2*akrypt_max_icode_size+2];
  char flongname[FILENAME_MAX];

 /* файл для вывода результатов не хешируем */
  if( ic->outfp != NULL ) {
   #ifdef _WIN32
    GetFullPathName( filename, FILENAME_MAX, flongname, NULL );
   #else
    realpath( filename, flongname );
   #endif
    if( !strncmp( flongname, ic->outfile, FILENAME_MAX - 2 )) return ak_error_ok;
  }

 /* теперь собственно хеширование */
  ak_error_set_value( ak_error_ok );
  ak_hash_file( ic->handle, filename, out );
  if(( error = ak_error_get_value( )) != ak_error_ok )
    ak_error_message_fmt( error, __func__, "incorrect integrity code for file %s", filename );
   else {
          ak_ptr_to_hexstr_static( out, ak_hash_get_icode_size( ic->handle ),
                                                outstr, 2*akrypt_max_icode_size+2, ak_false );
          fprintf( ic->outfp, "%s %s\n", outstr, filename );
          ak_error_set_value( ak_error_ok );
        }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_icode_check_function( char *string, ak_pointer ptr )
{
  int error = ak_error_ok;
  size_t offset = 0, isize = 0;
  struct icode_info *ic = ptr;
  ak_uint8 preout[akrypt_max_icode_size], out[akrypt_max_icode_size];

 /* проверяем, что дескриптор задан корректно */
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                    "using null pointer to hash function handle" );
 /* проверяем, что строка достаточно длинная */
  isize = ak_hash_get_icode_size( ic->handle );
  if(( offset = 2*isize) + 1 >= strlen( string ))
    return ak_error_message_fmt( ak_error_wrong_length, __func__ ,
                                                       "unexpected length of line: [%s]", string );
 /* увеличиваем счетчик обработанных файлов */
  ic->total++;

 /* получаем хеш из файла */
  string[offset] = 0;
  memset( preout, 0, akrypt_max_icode_size );
  ak_hexstr_to_ptr( string, preout, offset, ak_false );
  offset++;

 /* вычисляем хеш и проверяем равенство */
  memset( out, 0, akrypt_max_icode_size );
  ak_error_set_value( ak_error_ok );
  ak_hash_file( ic->handle, string+offset, out );

  if(( error = ak_error_get_value()) != ak_error_ok ) {
    fprintf( ic->outfp, "%s No!\n", string+offset );
    return ak_error_message_fmt( error, __func__ ,
                                     "wrong calculation of hash code for file %s", string+offset );
  }
 /* сравниваем */
  fprintf( ic->outfp, "%s ", string+offset );
  if( ak_ptr_is_equal( out, preout, isize )) {
    ic->successed++;
    fprintf( ic->outfp, "Ok\n" );
    return ak_error_ok;
  }

  fprintf( ic->outfp, "No!\n");
 return ak_error_not_equal_data;
}

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_icode_help( void )
{
  printf("akrypt icode [options] [directories or files]  - calculation and checking integrity codes for given files\n\n");
  printf("available options:\n");
  printf(" -a, --algorithm <ni>    set the algorithm, where \"ni\" is name or identifier of hash, mac or sign function\n");
  printf("                         default algorithm is icode function \"streebog256\"\n");
  printf(" -c, --check <file>      check previously generated integrity codes\n");
  printf(" -o, --output <file>     set the output file for generated integrity codes\n");
  printf(" -p, --pattern <str>     set the pattern which is used to find files\n");
  printf(" -r, --recursive         recursive search of files\n");
  printf("     --audit <file>      set the output file for errors and libakrypt audit system messages\n");
  printf(" -h, --help              show this information\n\n");

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                  akrypt_show.c  */
/* ----------------------------------------------------------------------------------------------- */
