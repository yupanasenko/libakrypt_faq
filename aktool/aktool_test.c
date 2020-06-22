 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <aktool.h>

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_help( void );

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test( int argc, TCHAR *argv[] )
{
  int next_option = 0, exit_status = EXIT_SUCCESS;
  enum { do_nothing, do_dynamic } work = do_nothing;

  const struct option long_options[] = {
     { "dynamic-control",  0, NULL, 255 },

     { "openssl-style",    0, NULL,   5 },
     { "audit",            1, NULL,   4 },
     { "dont-use-colors",  0, NULL,   3 },
     { "audit-file",       1, NULL,   2 },
     { "help",             0, NULL,   1 },
     { NULL,               0, NULL,   0 }
  };

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "", long_options, NULL );
       switch( next_option )
      {
         case  1  : return aktool_test_help();
         case  2  : /* получили от пользователя имя файла для вывода аудита */
                     aktool_set_audit( optarg );
                     break;
         case  3  : /* установка флага запрета вывода символов смены цветовой палитры */
                     ak_libakrypt_set_color_output( ak_false );
                     break;
         case  4  : /* устанавливаем уровень аудита */
                     aktool_log_level = atoi( optarg );
                     break;
         case  5  : /* переходим к стилю openssl */
                     aktool_openssl_compability = ak_true;
                     break;

         case 255 : /* тест скорости функций хеширования */
                     work = do_dynamic;
                     break;

         default:   /* обрабатываем ошибочные параметры */
                     if( next_option != -1 ) work = do_nothing;
                     break;
       }
   } while( next_option != -1 );
   if( work == do_nothing ) return aktool_test_help();

 /* начинаем работу с криптографическими примитивами */
   if( !aktool_create_libakrypt( )) return EXIT_FAILURE;

 /* выбираем заданное пользователем действие */
    switch( work )
   {
     case do_dynamic:
       if( ak_libakrypt_dynamic_control_test( )) printf(_("dynamic test is Ok\n"));
        else {
          printf(_("dynamic test is Wrong\n"));
          exit_status = EXIT_FAILURE;
        }
       break;

     default:  break;
   }

 /* завершаем работу и выходим */
   aktool_destroy_libakrypt();

 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_help( void )
{
  printf(
   _("aktool test [options]  - run various tests\n\n"
     "available options:\n"
     "     --dynamic           dynamic test of cryptographic algorithms\n"
     "                         runs all available algorithms on test values taken from standards and recommendations\n"
     "\n"
     "for more information run tests with \"--audit-file stderr\" option or see /var/log/auth.log file\n"
  ));

 return aktool_print_common_options();
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                  aktool_test.c  */
/* ----------------------------------------------------------------------------------------------- */
