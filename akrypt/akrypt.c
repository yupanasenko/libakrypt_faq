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
/*   akrypt.c                                                                                      */
/* ----------------------------------------------------------------------------------------------- */
 #include <akrypt.h>
 #include <getopt.h>

/* ----------------------------------------------------------------------------------------------- */
/* имя пользовательского файла для вывода аудита */
 char log_filename[1024];
 ak_function_log *logfunc = NULL;

/* ----------------------------------------------------------------------------------------------- */
 int main( int argc, char *argv[] )
{
 /* проверяем, что пользователем должна быть задана команда */
  if( argc < 2 ) return show_litehelp();

 /* проверяем флаги вывода справочной информации */
  if( akrypt_check_command( "-h", argv[1] )) return show_help();
  if( akrypt_check_command( "--help", argv[1] )) return show_help();
  if( akrypt_check_command( "/?", argv[1] )) return show_help();

  if( akrypt_check_command( "oid", argv[1] )) return oid( argc, argv );

 /* ничего не подошло, выводим сообщение об ошибке */
  printf("wrong command: %s\n", argv[1] );

 return EXIT_FAILURE;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_bool akrypt_check_command( const char *comm, char *argv )
{
 size_t len = strlen( comm );

  if( strlen( argv ) != len ) return ak_false;
  if( strncmp( comm, argv, len )) return ak_false;

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/* вывод сообщений в заданный пользователем файл, а также в стандартный демон вывода сообщений */
 int ak_function_log_user( const char *message )
{
  FILE *fp = fopen( log_filename, "a+" );
   /* функция выводит сообщения в заданный файл */
    if( !fp ) return ak_error_open_file;
    fprintf( fp, "%s\n", message );
#ifdef __linux__
    ak_function_log_syslog( message );
#endif
    if( fclose(fp) == EOF ) return ak_error_access_file;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                 реализация вывода справки                                       */
/* ----------------------------------------------------------------------------------------------- */
 int show_litehelp( void )
{
  printf("akrypt (crypto application based on libakrypt library, version: %s)\n",
                                                                         ak_libakrypt_version( ));
  printf("try \"akrypt --help\" to get more information\n");
 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int show_help( void )
{
  printf("akrypt (crypto application based on libakrypt library, version: %s)\n",
                                                                         ak_libakrypt_version( ));
  printf("usage \"akrypt command [options] [files]\"\n\n");
  printf("available commands:\n");
  printf("  oid     show information about libakrypt OID's\n\n");
  printf("try \"akrypt command --help\" to get information about command options\n");
  printf("try \"man akrypt\" to get more information about akrypt programm and somw examples\n");

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       akrypt.c  */
/* ----------------------------------------------------------------------------------------------- */


// int next_option = 0;
// const struct option long_options[] = {
//   { "help",             0, NULL, 'h' },
//   { "logfile",          1, NULL, 255 },
//   { NULL,               0, NULL,   0 }
// };

///* случай запуска программы без параметров  */
// if( argc == 1 ) return show_litehelp();

///* разбираем простейшие опции командной строки */
// do{
//     next_option = getopt_long( argc, argv, "h", long_options, NULL );
//     switch( next_option )
//    {
//       case 'h' : return show_help();
//       case '?' : return show_help();
//       case 255 : /* получили от пользователя имя файла для вывода аудита */
//                  if( memcmp( "stderr", optarg, 6 ) == 0 )
//                    logfunc = ak_function_log_stderr;
//                    /* если задан stderr, то используем готовую функцию */
//                   else {
//                      memset( log_filename, 0, 1024 );
//                      strncpy( log_filename, optarg, 1022 );
//                      logfunc = ak_function_log_user;
//                   }
//                   break;
//    }
//  } while( next_option != -1 );

///* инициализируем библиотеку */
// if( ak_libakrypt_create( logfunc ) != ak_true ) return ak_libakrypt_destroy();

///* теперь мы можем обработать заданные пользователем команды */
// if( akrypt_check_command( "oid", argv[1] )) return oid( argc, argv );

//return ak_libakrypt_destroy();


// /* флаги вывода справочной информации */
//   if( akrypt_check_command( "-h", argv[1] )) return show_help();
//   if( akrypt_check_command( "--help", argv[1] )) return show_help();
//   if( akrypt_check_command( "/?", argv[1] )) return show_help();

//  printf("unexpected command %s\n", argv[1] );
// return show_help( );

// /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
//  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
//    return ak_libakrypt_destroy();

//  printf("Hello world\n");
// return ak_libakrypt_destroy();
