 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <akrypt.h>

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_show_help( void );

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_show( int argc, TCHAR *argv[] )
{
  size_t i = 0;
  int next_option = 0, show_caption = ak_true;
  enum { do_nothing, do_alloids, do_oid, do_engines, do_modes, do_options } work = do_nothing;
  char *value = NULL;
  oid_engines_t engine = 0;
  oid_modes_t mode = 0;
  char algorithmName[128], algorithmOID[128];

  const struct option long_options[] = {
     { "help",             0, NULL,  'h' },
     { "audit",            1, NULL,  255 },
     { "oids",             0, NULL,  254 },
     { "oid",              1, NULL,  253 },
     { "engines",          0, NULL,  252 },
     { "options",          0, NULL,  251 },
     { "without-caption",  0, NULL,  250 },
     { "modes",            0, NULL,  249 },
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
   if( work == do_nothing ) return akrypt_show_help();

 /* начинаем работу с криптографическими примитивами */
   if( ak_libakrypt_create( audit ) != ak_true ) return ak_libakrypt_destroy();

 /* выбираем заданное пользователем действие */
    switch( work )
   {
     case do_alloids: /* выводим список всех доступных oid */
       if( show_caption ) {
         printf(" %-40s %-16s %-14s %s\n", _("Name"), _("Engine"), _("Mode"), "OID" );
         printf("-----------------------------------------------------------------------------------------------\n");
       }
       for( i = 0; i < ak_libakrypt_oids_count(); i++ ) {
          if( ak_libakrypt_get_oid_by_index( i, &engine, &mode,
                algorithmName, sizeof( algorithmName ), algorithmOID, sizeof( algorithmOID )) == ak_error_ok )
            printf(" %-40s %-16s %-14s %s\n", algorithmName, ak_libakrypt_get_engine_name( engine ),
                                                            ak_libakrypt_get_mode_name( mode ), algorithmOID );
       }
       break;

     case do_oid: /* выводим список тех, кто подходит под заданный шаблон */
       if( show_caption ) {
         printf(" %-40s %-16s %-14s %s\n", _("Name"), _("Engine"), _("Mode"), "OID" );
         printf("-----------------------------------------------------------------------------------------------\n");
       }
       for( i = 0; i < ak_libakrypt_oids_count(); i++ ) {
          const char *enginestr = NULL;
          if( ak_libakrypt_get_oid_by_index( i, &engine, &mode,
            algorithmName, sizeof( algorithmName ), algorithmOID, sizeof( algorithmOID )) != ak_error_ok ) continue;

         /* проверяем совпадение имени */
          enginestr = ak_libakrypt_get_engine_name( engine );
          if( strstr( algorithmName, value ) != NULL ) {
            printf(" %-40s %-16s %-14s %s\n", algorithmName, enginestr,
                                                         ak_libakrypt_get_mode_name( mode ), algorithmOID );
            continue;
          }
         /* проверяем совпадение с engine */
          if( strstr( enginestr, value ) != NULL ) {
            printf(" %-40s %-16s %-14s %s\n", algorithmName, enginestr,
                                                         ak_libakrypt_get_mode_name( mode ), algorithmOID );
            continue;
          }
         /* в заключение, проверяем OID*/
          if( strstr( algorithmOID, value) != NULL ) {
            printf(" %-40s %-16s %-14s %s\n", algorithmName, enginestr,
                                                         ak_libakrypt_get_mode_name( mode ), algorithmOID );
            continue;
          }
       }
       break;

     case do_options:
       if( show_caption ) {
         printf(" %-40s %-16s\n", _("Option"), _("Value"));
         printf("------------------------------------------------------\n");
       }
       for( i = 0; i < ak_libakrypt_options_count(); i++ )
          printf(" %-40s %-16ld\n", ak_libakrypt_get_option_name( i ),
                                                    (long int) ak_libakrypt_get_option_value( i ));
       break;

     case do_engines:
      if( show_caption ) {
        printf(" %-40s \n", _("Engine"));
        printf("------------------------------------------------------\n");
      }
      do {
          printf(" %-25s\n", ak_libakrypt_get_engine_name( engine ));
      } while( engine++ < undefined_engine );
      break;

     case do_modes:
      if( show_caption ) {
        printf(" %-40s \n", _("Mode"));
        printf("------------------------------------------------------\n");
      }
      do {
            printf(" %-25s\n", ak_libakrypt_get_mode_name( mode ));
      } while( mode++ < undefined_mode );
      break;
     default:  break;
   }

 /* завершаем работу и выходим */
 return ak_libakrypt_destroy();
}

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_show_help( void )
{
  printf(_("akrypt show [options]  - show useful information about user and libakrypt parameters\n\n"));
  printf(_("available options:\n"));
  printf(_("     --engines           show all types of available crypto engines\n"));
  printf(_("     --oid <eni>         show one or more OID's, where \"eni\" is an engine, name or identifier of OID\n"));
  printf(_("     --oids              show the list of all available libakrypt's OIDs\n"));
  printf(_("     --options           show the list of all libakrypt's cryptographic options and their values\n"));
  printf(_("     --modes             show all types of cryptographic modes\n"));
  printf(_("     --without-caption   don't show a caption for displayed values\n"));

  printf(_("\ncommon options:\n"));
  printf(_("     --audit <file>      set the output file for errors and libakrypt audit system messages\n" ));
  printf(_(" -h, --help              show this information\n\n"));

 return EXIT_SUCCESS;
}

