 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <aktool.h>

/* ----------------------------------------------------------------------------------------------- */
 int aktool_show_help( void );

/* ----------------------------------------------------------------------------------------------- */
 int aktool_show( int argc, TCHAR *argv[] )
{
  size_t idx = 0;
  int next_option = 0, show_caption = ak_true;
  enum { do_nothing, do_alloids, do_oid, do_engines, do_modes, do_options } work = do_nothing;

 /* параметры, запрашиваемые пользователем */
  char *value = NULL;
  oid_modes_t mode = 0;
  oid_engines_t engine = 0;
  const char *oid, **names;

  const struct option long_options[] = {
     { "oids",             0, NULL,  254 },
     { "oid",              1, NULL,  253 },
     { "engines",          0, NULL,  252 },
     { "options",          0, NULL,  251 },
     { "without-caption",  0, NULL,  250 },
     { "modes",            0, NULL,  249 },

     { "dont-use-colors",  0, NULL,   3 },
     { "audit",            1, NULL,   2  },
     { "help",             0, NULL,   1  },
     { NULL,               0, NULL,   0  }
  };

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "", long_options, NULL );
       switch( next_option )
      {
         case  1  : return aktool_show_help();
         case  2  : /* получили от пользователя имя файла для вывода аудита */
                     aktool_set_audit( optarg );
                     break;
         case  3  : /* установка флага запрета вывода символов смены цветовой палитры */
                     ak_libakrypt_set_color_output( ak_false );

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
         case 250:  /* запрещаем выводить заголовок */
                     show_caption = ak_false;
                     break;
         case 249:   work = do_modes;
                     break;

         default:   /* обрабатываем ошибочные параметры */
                     if( next_option != -1 ) work = do_nothing;
                     break;
       }
   } while( next_option != -1 );
   if( work == do_nothing ) return aktool_show_help();

 /* начинаем работу с криптографическими примитивами */
   if( ak_libakrypt_create( audit ) != ak_true ) return ak_libakrypt_destroy();

 /* выбираем заданное пользователем действие */
    switch( work )
   {
     case do_alloids: /* выводим список всех доступных oid */
       if( show_caption ) {
         printf("  N  %-22s %-40s %-20s %-20s\n", _("oid"), _("name(s)"), _("engine"), _("mode") );
         printf(" -----------------------------------------------------");
         printf("------------------------------------------------------\n");
       }

       for( idx = 0; idx < ak_libakrypt_oids_count(); idx++ ) {
          size_t jdx = 0;
         /* получаем информацию об идентифкаторе с заданным номером */
          if(( ak_libakrypt_get_oid_by_index( idx, &engine, &mode,
                                                            &oid, &names )) != ak_error_ok ) break;
          if( names[0] == NULL ) break;

         /* выводим сначала с одним именем  */
          printf("%3u  %-22s %-40s %-20s %-20s\n",
            (unsigned int) idx, oid, names[0], ak_libakrypt_get_engine_name( engine ),
                                                               ak_libakrypt_get_mode_name( mode ));
         /* потом выводим остальные имена идентификатора */
          while( names[++jdx] != NULL ) printf("%28s%s\n", " ", names[jdx] );
       }
       break;

     case do_oid: /* выводим список тех, кто подходит под заданный шаблон */
       if( show_caption ) {
         printf("  N  %-22s %-40s %-20s %-20s\n", _("oid"), _("name(s)"), _("engine"), _("mode") );
         printf(" -----------------------------------------------------");
         printf("------------------------------------------------------\n");
       }

       for( idx = 0; idx < ak_libakrypt_oids_count(); idx++ ) {
          size_t jdx = 0;
         /* получаем информацию об идентифкаторе с заданным номером */
          if(( ak_libakrypt_get_oid_by_index( idx, &engine, &mode,
                                                            &oid, &names )) != ak_error_ok ) break;
          if( names[0] == NULL ) break;

         /* проверяем тип криптопреобразования (engine) */
          if( strstr( ak_libakrypt_get_engine_name(engine), value ) != NULL ) {
            /* выводим первое имя */
             printf("%3u  %-22s %-40s %-20s %-20s\n",
               (unsigned int) idx, oid, names[0], ak_libakrypt_get_engine_name( engine ),
                                                               ak_libakrypt_get_mode_name( mode ));
            /* потом все остальные */
             while( names[++jdx] != NULL ) printf("%28s%s\n", " ", names[jdx] );
            continue;
          }

         /* проверяем идентификатор (oid) */
          if( strstr( oid, value ) != NULL ) {
            /* выводим первое имя */
             printf("%3u  %-22s %-40s %-20s %-20s\n",
               (unsigned int) idx, oid, names[0], ak_libakrypt_get_engine_name( engine ),
                                                               ak_libakrypt_get_mode_name( mode ));
            /* потом все остальные */
             while( names[++jdx] != NULL ) printf("%28s%s\n", " ", names[jdx] );
            continue;
          }

         /* последнее - поиск по имени */
          jdx = 0;
          while( names[jdx] != NULL ) {
            if( strstr( names[jdx], value ) != NULL ) {
             printf("%3u  %-22s %-40s %-20s %-20s\n",
               (unsigned int) idx, oid, names[jdx], ak_libakrypt_get_engine_name( engine ),
                                                               ak_libakrypt_get_mode_name( mode ));
            }
            jdx++;
          }

       } /* конец for */
       break;

     case do_options:
       if( show_caption ) {
         printf(" %-40s %-16s\n", _("option"), _("value"));
         printf("------------------------------------------------------\n");
       }
       for( idx = 0; idx < ak_libakrypt_options_count(); idx++ )
          printf(" %-40s %-16ld\n", ak_libakrypt_get_option_name( idx ),
                                                  (long int) ak_libakrypt_get_option_value( idx ));
       break;

     case do_engines:
       if( show_caption )
         printf(" %s\n------------------------------------------------------\n", _("engine"));
       do {
           printf(" %s\n", ak_libakrypt_get_engine_name( engine ));
       } while( engine++ < undefined_engine );
       break;

     case do_modes:
       if( show_caption )
         printf(" %s\n------------------------------------------------------\n", _("mode"));
       do {
            printf(" %s\n", ak_libakrypt_get_mode_name( mode ));
       } while( mode++ < undefined_mode );
       break;

     default:  break;
   }

 /* завершаем работу и выходим */
 return ak_libakrypt_destroy();
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_show_help( void )
{
  printf(_("aktool show [options]  - show useful information about libakrypt parameters\n\n"));
  printf(_("available options:\n"));
  printf(_("     --engines           show all types of available crypto engines\n"));
  printf(_("     --oid <eni>         show one or more OID's, where \"eni\" is an engine, name or identifier of OID\n"));
  printf(_("     --oids              show the list of all available libakrypt's OIDs\n"));
  printf(_("     --options           show the list of all libakrypt's cryptographic options and their values\n"));
  printf(_("     --modes             show all types of cryptographic modes\n"));
  printf(_("     --without-caption   don't show a caption for displayed values\n"));

 return aktool_print_common_options();
}

