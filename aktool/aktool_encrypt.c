/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2019 - 2021 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Прикладной модуль, реализующий процедуры шифрования файлов                                     */
/*                                                                                                 */
/*  aktool_encdrypt.c                                                                              */
/* ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <aktool.h>

/* ----------------------------------------------------------------------------------------------- */
 int aktool_encrypt_help( void );
 int aktool_encrypt_work( int argc, tchar *argv[] );
 int aktool_decrypt_work( int argc, tchar *argv[] );

/* ----------------------------------------------------------------------------------------------- */
 int aktool_encrypt( int argc, tchar *argv[], encrypt_t work )
{
  int next_option = 0, exitcode = EXIT_FAILURE;

 /* параметры, запрашиваемые пользователем */
  const struct option long_options[] = {

      aktool_common_functions_definition,
     { NULL,               0, NULL,   0  },
  };

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "h", long_options, NULL );
       switch( next_option )
      {
        aktool_common_functions_run( aktool_encrypt_help );

        default:   /* обрабатываем ошибочные параметры */
                     if( next_option != -1 ) work = do_nothing;
                     break;
      }
   } while( next_option != -1 );
   if( work == do_nothing ) return aktool_encrypt_help();

 /* начинаем работу с криптографическими примитивами */
   if( !aktool_create_libakrypt( )) return EXIT_FAILURE;

 /* основная часть */
    switch( work )
   {
     case do_encrypt: /* зашифровываем данные */
       exitcode = aktool_encrypt_work( argc, argv );
       break;

     case do_decrypt: /* расшифровываем данные */
       exitcode = aktool_decrypt_work( argc, argv );
       break;

     default:
       break;
   }

 /* завершаем работу и выходим */
   aktool_destroy_libakrypt();

 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
/*                          Реализация процедуры зашифрования файла                                */
/* ----------------------------------------------------------------------------------------------- */
 int aktool_encrypt_work( int argc, tchar *argv[] )
{
  int errcount = 0;

  /* пропускаем команду - e или encrypt */
   ++optind;
   if( optind >= argc ) {
     aktool_error(_(
                 "the name of file or directory is not specified as the argument of the program"));
     return EXIT_FAILURE;
   }

  /* основной перебор заданных пользователем файлов и каталогов */
   while( optind < argc ) {
     char *value = argv[optind++];
     switch( ak_file_or_directory( value )) {
        case DT_DIR:
          break;

        case DT_REG:
          break;

        default: aktool_error(_("%s is unsupported argument"), value ); errcount++;
          break;
     }
   }

 /* проверяем на наличие ошибок */
   if( errcount ) {
     if( !ki.quiet ) aktool_error(_("aktool found %d error(s), "
            "rerun aktool with \"--audit-file stderr\" option or see syslog messages"), errcount );
     return EXIT_FAILURE;
   }

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
/*                          Реализация процедуры расшифрования файла                               */
/* ----------------------------------------------------------------------------------------------- */
 int aktool_decrypt_work( int argc, tchar *argv[] )
{
  aktool_error( "this function is not implemented yet, sorry ... " );
 return EXIT_FAILURE;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_encrypt_help( void )
{
  printf(
   _("aktool encrypt/decrypt [options] [files or directories] - file encryption and decryption features\n\n"
     "available options:\n"
  ));

 return aktool_print_common_options();
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                              aktool_encrypt.c   */
/* ----------------------------------------------------------------------------------------------- */

