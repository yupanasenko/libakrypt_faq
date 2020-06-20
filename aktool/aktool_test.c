 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <aktool.h>

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_help( void );

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test( int argc, TCHAR *argv[] )
{
  int next_option = 0;
  enum { do_nothing, do_hash } work = do_nothing;

  const struct option long_options[] = {
     { "hash",             0, NULL,  254 },

     { "audit",            1, NULL,   4  },
     { "dont-use-colors",  0, NULL,   3  },
     { "audit-file",       1, NULL,   2  },
     { "help",             0, NULL,   1  },
     { NULL,               0, NULL,   0  }
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

         case 254 : /* тест скорости функций хеширования */
                     work = do_hash;
                     break;

         default:   /* обрабатываем ошибочные параметры */
                     if( next_option != -1 ) work = do_nothing;
                     break;
       }
   } while( next_option != -1 );
   if( work == do_nothing ) return aktool_test_help();

 /* начинаем работу с криптографическими примитивами */
   if( ak_libakrypt_create( audit ) != ak_true ) return ak_libakrypt_destroy();
   ak_log_set_level( aktool_log_level );

 /* выбираем заданное пользователем действие */
    switch( work )
   {
     case do_hash:
       break;

     default:  break;
   }

 /* завершаем работу и выходим */
 return ak_libakrypt_destroy();
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_test_help( void )
{
  printf(_("aktool test [options]  - run various tests\n\n"));
  printf(_("available options:\n"));
  printf(_("     --hash              test of hash functions speed\n"));

 return aktool_print_common_options();
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                  aktool_test.c  */
/* ----------------------------------------------------------------------------------------------- */
