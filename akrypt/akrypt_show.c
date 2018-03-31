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
/*   akrypt_show.c                                                                                 */
/* ----------------------------------------------------------------------------------------------- */
 #include <akrypt.h>

/* ----------------------------------------------------------------------------------------------- */
/* вывод в консоль информации об OID */
 void akrypt_show_oid( ak_handle handle )
{
  printf("%s (%s) ", ak_libakrypt_oid_get_name( handle ), ak_libakrypt_oid_get_id( handle ));
  printf("[%s, %s]\n", ak_libakrypt_oid_get_engine_str( handle ),
                                                    ak_libakrypt_oid_get_mode_str( handle ));
}

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_show_help( void )
{
  printf("akrypt show [options]  - show useful information about user and libakrypt parameters\n\n");
  printf("available options:\n");
  printf("     --engines           show all types of available crypto engines\n");
  printf("     --oid <eni>         show one or more OID's, where \"eni\" is engine, name or identifier of OID\n");
  printf("                         (if engine is \"undefined_engine\" then show list of all available OID's)\n");
  printf("     --oids              show the list of all available libakrypt's OIDs\n");
  printf("     --options           show the list of all libakrypt's cryptographic options and their values\n");
  printf("     --audit <file>      set the output file for errors and audit system messages\n");
  printf(" -h, --help              show this information\n\n");

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_show( int argc, char *argv[] )
{
  size_t i = 0;
  int next_option = 0;
  enum { do_nothing, do_alloids, do_oid, do_engines, do_options } work = do_nothing;
  ak_oid_engine engine = undefined_engine;
  ak_handle handle = ak_error_wrong_handle;
  char *value = NULL;

  const struct option long_options[] = {
     { "help",             0, NULL,  'h' },
     { "audit",            1, NULL,  255 },
     { "oids",             0, NULL,  254 },
     { "oid",              1, NULL,  253 },
     { "engines",          0, NULL,  252 },
     { "options",          0, NULL,  251 },
     { NULL,               0, NULL,   0  }
  };

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "h", long_options, NULL );
       switch( next_option )
      {
         case 'h' : return akrypt_show_help();
         case 255 : /* получили от пользователя имя файла для вывода аудита */
                     akrypt_set_audit( optarg );
                     break;

         case 254 : /* выводим список всех доступных oid */
                     work = do_alloids;
                     break;

         case 253 : /* производим поиск OID по параметрам */
                     work = do_oid; value = optarg;
                     break;

         case 252 : /* выводим список всех типов криптографических механизмов */
                     work = do_engines;
                     break;
         case 251 : /* выводим список всех опций библиотеки и их значений */
                     work = do_options;
                     break;

         default:   /* обрабатываем ошибочные параметры */
                     if( next_option != -1 ) work = do_nothing;
                     break;
       }
   } while( next_option != -1 );
   if( work == do_nothing ) return EXIT_FAILURE;

 /* начинаем работу с криптографическими примитивами */
   if( ak_libakrypt_create( audit ) != ak_true ) return ak_libakrypt_destroy();

 /* выбираем заданное пользователем действие */
    switch( work )
   {
     case do_alloids: /* выводим список всех доступных oid */
               handle = ak_libakrypt_find_oid_by_engine( undefined_engine );
               while( handle != ak_error_wrong_handle ) {
                /* выводим найденное */
                  akrypt_show_oid( handle );
                /* ищем следующий OID с тем же типом криптографического механизма */
                  handle = ak_libakrypt_findnext_oid_by_engine( handle, engine );
               }
               break;

     case do_oid:
               /* сначала поиск по имени */
               if(( handle = ak_libakrypt_find_oid_by_name( value )) != ak_error_wrong_handle ) {
                 akrypt_show_oid( handle );
                 break;
               }
               /* потом поиск по идентификатору */
               if(( handle = ak_libakrypt_find_oid_by_id( value )) != ak_error_wrong_handle ) {
                 akrypt_show_oid( handle );
                 break;
               }
               /* в заключение - поиск по типу криптографического механизма */
               ak_error_set_value( ak_error_ok );
               if(( engine = ak_libakrypt_get_engine( value )) != undefined_engine ) {
                 handle = ak_libakrypt_find_oid_by_engine( engine );
                 while( handle != ak_error_wrong_handle ) {
                  /* выводим найденное */
                   akrypt_show_oid( handle );
                  /* ищем следующий OID с тем же типом криптографического механизма */
                   handle = ak_libakrypt_findnext_oid_by_engine( handle, engine );
                 }
                 break;
               }
               printf("string \"%s\" is not valid engine, name or identifier of OID\n", value );
               break;

     case do_engines:
               for( i = 0; i < ak_libakrypt_engines_count(); i++ )
                  printf("%s\n", ak_libakrypt_get_engine_str( i ));
               break;

     case do_options:
               for( i = 0; i < ak_libakrypt_options_count(); i++ )
                  printf("%s = %d\n",
                         ak_libakrypt_get_option_name( i ), ak_libakrypt_get_option_value( i ));
               break;

     default:  break;
   }

 /* завершаем работу и выходим */
 return ak_libakrypt_destroy();
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                  akrypt_show.c  */
/* ----------------------------------------------------------------------------------------------- */
