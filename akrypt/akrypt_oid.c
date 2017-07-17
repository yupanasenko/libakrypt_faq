 #include <getopt.h>
 #include <akrypt.h>
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
/*   реализация команды oid, связанной с использованием идентификаторов криптографических мех-мов  */
/* ----------------------------------------------------------------------------------------------- */
 void show_oid( ak_handle handle )
{
  printf("%s: ", ak_handle_get_engine_str( handle ));
  printf("%s (%s) ", ak_oid_get_name( handle ), ak_oid_get_id( handle ));
  printf("[%s, %s]\n", ak_oid_get_engine_str( handle ), ak_oid_get_mode_str( handle ));
}

/* ----------------------------------------------------------------------------------------------- */
 int show_oid_help( void )
{
  printf("akrypt oid [options]  - show information about libakrypt OID's\n\n");
  printf("available options:\n");
  printf(" -e, --engine <engine>  show the list of available OID's with given engine\n");
  printf("                        if engine is \"undefined_engine\" then show list of all\n");
  printf("                        available OID's\n");
  printf(" -s, --show-engines     show the list of all available engines\n");
  printf(" -n, --name <name>      show OID with given name\n");
  printf(" -i, --id <id>          show OID with given identifier\n");
  printf("     --logfile <file>   set the file for errors and audit system messages\n");
  printf(" -h, --help             show this information\n\n");
  printf("akrypt oid without options show all available OID's\n");

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int oid( int argc, char *argv[] )
{
  int next_option = 0;
  enum { do_nothing, do_engine, do_name, do_id, do_show_engines } work = do_engine;

  ak_oid_engine engine = undefined_engine;
  ak_handle handle = ak_error_wrong_handle;
  char *value = NULL;

  const struct option long_options[] = {
    { "help",             0, NULL,  'h' },
    { "engine",           1, NULL,  'e' },
    { "name",             1, NULL,  'n' },
    { "id",               1, NULL,  'i' },
    { "show-engines",     0, NULL,  's' },
    { "logfile",          1, NULL,  255 },
    { NULL,               0, NULL,   0  }
  };

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "he:n:i:s", long_options, NULL );
       switch( next_option )
      {
         case 'h' : return show_oid_help();
         case 255 : /* получили от пользователя имя файла для вывода аудита */
                    if( ak_ptr_is_equal( "stderr", optarg, 6 ))
                      logfunc = ak_function_log_stderr;
                      /* если задан stderr, то используем готовую функцию */
                     else {
                           memset( log_filename, 0, 1024 );
                           strncpy( log_filename, optarg, 1022 );
                           logfunc = ak_function_log_user;
                          }
                    break;
         case 's' : work = do_show_engines;
                    break;
         case 'i' : work = do_id; value = optarg;
                    break;
         case 'n' : work = do_name; value = optarg;
                    break;
         case 'e' : work = do_engine;
                   /* здесь мы отлавливаем ошибки преобразования, которые не выводятся в логгер */
                    ak_error_set_value( ak_error_ok );
                    if(( engine = ak_engine_str( optarg )) == undefined_engine ) {
                      if( ak_error_get_value() != ak_error_ok )
                        printf("warning: wrong engine \"%s\", using \"undefined_engine\"\n", optarg );
                    }
                    break;
                   /* обрабатываем ошибочнве параметры */
         default:   if( next_option != -1 ) work = do_nothing;
                    break;
      }
  } while( next_option != -1 );
  if( work == do_nothing ) return EXIT_FAILURE;

 /* начинаем работу с криптографическими примитивами */
  if( ak_libakrypt_create( logfunc ) != ak_true ) return ak_libakrypt_destroy();

 /* выбираем заданное пользователем действие */
   switch( work )
  {
    case do_show_engines: for( next_option = 0; next_option < ak_engine_count(); next_option++ )
                             printf("%s\n", ak_engine_get_str( next_option ));
                          break;

    case do_name:         if(( handle = ak_oid_find_by_name( value )) != ak_error_wrong_handle )
                            show_oid( handle );
                           else printf("given name \"%s\" not found\n", value );
                          break;

    case do_id:           if(( handle = ak_oid_find_by_id( value )) != ak_error_wrong_handle )
                            show_oid( handle );
                           else printf("given identifier \"%s\" not found\n", value );
                          break;
    case do_engine:
    default:  /* выводим список доступных OID'oв с заданным типом  */
              /* находим первый OID с заданным пользователем типом криптографического механизма */
                  handle = ak_oid_find_by_engine( engine );
                  while( handle != ak_error_wrong_handle ) {
                    /* выводим найденное */
                     show_oid( handle );
                    /* ищем следующий OID с тем же типом криптографического механизма */
                     handle = ak_oid_findnext_by_engine( handle, engine );
                  }
                  break;
  }

 /* завершаем работу и выходим */
 return ak_libakrypt_destroy();
}
