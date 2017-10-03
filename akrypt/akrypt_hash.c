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
/*   akrypt_hash.c                                                                                 */
/* ----------------------------------------------------------------------------------------------- */
 #include <akrypt.h>

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_hash_help( void )
{
  printf("akrypt hash [options] [directories or files]  - calculating and checking control sums for various hash functions\n\n");
  printf("available options:\n");
  printf(" -a, --algorithm <ni>    set the hashing algorithm, where \"ni\" is name or identifier of hash function\n");
  printf("                         default value of hash algorithm is \"streebog256\"\n");
  printf(" -p, --pattern <str>     set the pattern which is used to find hashing files\n");
  printf(" -r, --recursive         recursive search of hashing files\n");
  printf("     --audit <file>      set the output file for errors and audit system messages\n");
  printf(" -h, --help              show this information\n\n");

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_hash_function( ak_handle handle, const char *filename )
{
  int error = ak_error_ok;
  ak_uint8 out[64], outstr[130];

  ak_error_set_value( ak_error_ok );
  ak_hash_file( handle, filename, out );
  if(( error = ak_error_get_value( )) != ak_error_ok )
    ak_error_message_fmt( error, __func__, "incorrect hash code for file %s", filename );
   else {
          ak_ptr_to_hexstr_static( out, ak_hash_get_icode_size( handle ), outstr, 130, ak_false );
          fprintf( stdout, "%s %s\n", outstr, filename );
          ak_error_set_value( ak_error_ok );
        }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_hash( int argc, char *argv[] )
{
  int next_option = 0, idx = 0;
  enum { do_nothing, do_hash, do_check } work = do_hash;
  ak_handle oid_handle = ak_error_wrong_handle, handle = ak_error_wrong_handle;
  char *algorithm_ni = "streebog256", *pattern = "*";
  ak_bool tree = ak_false; /* флаг рекурсивной обработки файлов */

  const struct option long_options[] = {
     { "help",             0, NULL,  'h' },
     { "audit",            1, NULL,  255 },
     { "algorithm",        1, NULL,  'a' },
     { "pattern",          1, NULL,  'p' },
     { "recursive",        0, NULL,  'r' },
     { NULL,               0, NULL,   0  }
  };

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "ha:p:r", long_options, NULL );
       switch( next_option )
      {
         case 'h' : return akrypt_hash_help();
         case 255 : /* получили от пользователя имя файла для вывода аудита */
                     akrypt_set_audit( optarg );
                     break;

         case 'a' : /* устанавливаем алгоритм хеширования */
                     algorithm_ni = optarg;
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

 /* проверяем заданный пользователем алгоритм и создаем дескриптор алгоритма хеширования */
   if(( oid_handle = ak_oid_find_by_name( algorithm_ni )) == ak_error_wrong_handle ) {
      if(( oid_handle = ak_oid_find_by_id( algorithm_ni )) == ak_error_wrong_handle ) {
        printf("string \"%s\" is not valid name or identifier of hash function\n", algorithm_ni );
        return ak_libakrypt_destroy();
      }
   }
   if(( handle = ak_hash_new_oid( oid_handle )) == ak_error_wrong_handle ) {
     printf("incorrect descriptor of \"%s\" hash function\n", algorithm_ni );
     return ak_libakrypt_destroy();
   }

 /* выбираем заданное пользователем действие */
   switch( work )
  {
    case do_hash: /* вычисляем контрольную сумму */
                   for( idx = 1; idx < argc; idx++ ) {
                       int type = akrypt_file_or_directory( argv[idx] );
                       switch( type )
                      {
                       case DT_DIR: akrypt_find( argv[idx], pattern, akrypt_hash_function, handle, tree );
                                    break;
                       case DT_REG: akrypt_hash_function( handle, argv[idx] );
                                    break;
                       default:    /* убираем из списка параметры опций */
                                    if( !strcmp( argv[idx], "-p" )) idx++;
                                    if( !strcmp( argv[idx], "--pattern" )) idx++;
                                    if( !strcmp( argv[idx], "--audit" )) idx++;
                           break;
                      }
                   }
                   break;

    case do_check: /* проверяем контрольную сумму */

    default: break;
   }
 /* завершаем работу и выходим */
 return ak_libakrypt_destroy();
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                  akrypt_show.c  */
/* ----------------------------------------------------------------------------------------------- */
