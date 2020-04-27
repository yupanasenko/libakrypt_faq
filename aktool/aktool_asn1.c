 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <aktool.h>

/* ----------------------------------------------------------------------------------------------- */
 int aktool_asn1_help( void );

/* ----------------------------------------------------------------------------------------------- */
 int aktool_asn1( int argc, TCHAR *argv[] )
{
#ifdef _WIN32
  unsigned int cp = 0;
#endif
  int next_option = 0, idx = 0, error = ak_error_ok, ecount = 0;

  const struct option long_options[] = {
    /* сначала уникальные */

    /* потом общие */
     { "dont-use-colors",     0, NULL,   3 },
     { "audit",               1, NULL,   2 },
     { "help",                0, NULL,   1 },
     { NULL,                  0, NULL,   0 }
  };

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "", long_options, NULL );
       switch( next_option )
      {
       /* сначала обработка стандартных опций */
         case   1 :  return aktool_asn1_help();

         case   2 : /* получили от пользователя имя файла для вывода аудита */
                     aktool_set_audit( optarg );
                     break;
         case   3 : /* установка флага запрета вывода символов смены цветовой палитры */
                     ak_libakrypt_set_color_output( ak_false );
                     break;


       /* теперь опции, уникальные для asn1parse */

       /* обрабатываем ошибочные параметры */
         default:
                     break;
       }
  } while( next_option != -1 );

 /* если параметры определены некорректно, то выходим  */
  if( argc < 3 ) return aktool_asn1_help();

#ifdef _WIN32
  cp = GetConsoleCP();
  SetConsoleCP( 65001 );
  SetConsoleOutputCP( 65001 );
#endif

 /* начинаем работу с криптографическими примитивами */
  if( ak_libakrypt_create( audit ) != ak_true ) {
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }

 /* перебираем все доступные параметры командной строки */
  for( idx = 2; idx < argc; idx++ ) {
     if( aktool_file_or_directory( argv[idx] ) == DT_REG ) {
       if(( error = ak_libakrypt_print_asn1( stdout, argv[idx] )) != ak_error_ok ) {
         fprintf( stdout, _("file %s is wrong\n"), argv[idx] );
         ecount++;
       }
     }
  }
  ak_libakrypt_destroy();

#ifdef _WIN32
  SetConsoleCP( cp );
  SetConsoleOutputCP( cp );
#endif

  if( ecount ) {
    fprintf( stdout,
      _("aktool found %d error(s), rerun aktool with \"--audit stderr\" flag\n"), ecount );
    return EXIT_FAILURE;
  }
 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_asn1_help( void )
{
  printf(_("aktool asn1parse [options] [files] - decode and print ASN.1 data\n\n"));
  printf(_("available options:\n"));

 return aktool_print_common_options();
}
