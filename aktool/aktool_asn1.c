 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <aktool.h>

/* ----------------------------------------------------------------------------------------------- */
 int aktool_asn1_help( void );

/* ----------------------------------------------------------------------------------------------- */
 int aktool_asn1( int argc, TCHAR *argv[] )
{
  int next_option = 0, idx = 0;
  bool_t check_flag = ak_false;

  const struct option long_options[] = {
   /* сначала уникальные */
     { "check",               0, NULL,  254 },

    /* потом общие */
     { "audit",               1, NULL,   2  },
     { "help",                0, NULL,   1  },
     { NULL,                  0, NULL,   0  }
  };

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "", long_options, NULL );
       switch( next_option )
      {
       /* сначала обработка стандартных опций */
         case   1 : return aktool_asn1_help();

         case   2 : /* получили от пользователя имя файла для вывода аудита */
                     aktool_set_audit( optarg );
                     break;

         case  254: check_flag = ak_true;
                    break;

       /* теперь опции, уникальные для icode */
         default:   /* обрабатываем ошибочные параметры */
                     break;
       }

  } while( next_option != -1 );

 /* начинаем работу с криптографическими примитивами */
  if( ak_libakrypt_create( audit ) != ak_true ) {
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }

 /* перебираем все доступные параметры командной строки */
  for( idx = 2; idx < argc; idx++ ) {
     if( aktool_file_or_directory( argv[idx] ) == DT_REG ) {
       int error = ak_asn1_fprintf( stdout, argv[idx], check_flag );
       if( check_flag ) {
         if( error != ak_error_ok ) {
           fprintf( stdout,
                    "file %s is Wrong (for details run aktool with --audit flag)\n\n", argv[idx] );
         } else fprintf( stdout, "file %s is Ok\n\n", argv[idx] );
       }
     }
  }
  ak_libakrypt_destroy();
 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_asn1_help( void )
{
  printf(_("aktool asn1 [options] [files] - decode and print ASN.1 data\n\n"));
  printf(_("available options:\n"));
  printf(_("     --check             the input ASN.1 data correctness check\n"));

  printf(_("\ncommon aktool options:\n"));
  printf(_("     --audit <file>      set the output file for errors and libakrypt audit system messages\n" ));
  printf(_("     --help              show this information\n\n"));

 return EXIT_SUCCESS;
}
