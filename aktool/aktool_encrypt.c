/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2019 - 2021 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Прикладной модуль, реализующий процедуры шифрования файлов                                     */
/*                                                                                                 */
/*  aktool_encrypt.c                                                                               */
/* ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include "aktool.h"

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_ERRNO_H
 #include <errno.h>
#endif
#ifdef AK_HAVE_BZLIB_H
 #include <bzlib.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 int aktool_encrypt_help( void );
 int aktool_encrypt_work( int argc, tchar *argv[] );
 int aktool_decrypt_work( int argc, tchar *argv[] );

/* ----------------------------------------------------------------------------------------------- */
 int aktool_encrypt( int argc, tchar *argv[], encrypt_t work )
{
  ak_int64 size_value = 0;
  int next_option = 0, exitcode = EXIT_FAILURE;

 /* параметры, запрашиваемые пользователем */
  const struct option long_options[] = {
     { "pattern",             1, NULL,  'p' },
     { "recursive",           0, NULL,  'r' },
     { "output",              1, NULL,  'o' },
     { "mode",                1, NULL,  'm' },
     { "random-file",         1, NULL,  206 },
     { "random",              1, NULL,  205 },
     { "fs",                  1, NULL,  231 },
     { "fc",                  1, NULL,  232 },
     { "fr",                  0, NULL,  233 },

   #ifdef AK_HAVE_BZLIB_H
     { "bz2",                 0, NULL,  'j' },
   #endif
     
     aktool_common_functions_definition,
     { NULL,               0, NULL,   0  },
  };

 /* устанавливаем параметры программы в значения по-умолчанию */
  ki.method = ak_oid_find_by_name( "npecies-scheme-key" );
  ki.pattern =
 #ifdef _WIN32
   "*.*";
 #else
   "*";
 #endif
  ki.tree = ak_false;
 #ifdef AK_HAVE_BZLIB_H
  ki.compress_bz2 = ak_false;
 #endif
  ki.oid_of_generator = ak_oid_find_by_name( aktool_default_generator );

 /* настройки режима шифрования (по-умолчанию) */
  ki.heset.mode = ak_oid_find_by_name( "mgm-kuznechik" );
  ki.heset.fraction.mechanism = size_fraction;
  ki.heset.fraction.value = 16*ak_libakrypt_get_option_by_name( "kuznechik_cipher_resource" );
  ki.heset.scheme = npecies_scheme;


 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "hp:rjo:m:", long_options, NULL );
       switch( next_option )
      {
        aktool_common_functions_run( aktool_encrypt_help );

        case 'p' : /* устанавливаем дополнительную маску для поиска файлов */
                   ki.pattern = optarg;
                   break;

        case 'r' : /* устанавливаем флаг рекурсивного обхода каталогов */
                   ki.tree = ak_true;
                   break;

        case 'm' : /* устанавливаем режим шифрования */
                   if(( ki.heset.mode = ak_oid_find_by_ni( optarg )) == NULL ) {
                     aktool_error(
                        _("using unsupported name or identifier \"%s\" for encryption mode"),
                                                                                          optarg );
                     printf(
                        _("try \"aktool s --oid aead\" for list of all available identifiers\n"));
                     return EXIT_FAILURE;
                   }
                   if( ki.heset.mode->mode != aead ) {
                     aktool_error(_("using non aead object identifier \"%s\""), optarg );
                     printf(
                        _("try \"aktool s --oid aead\" for list of all available identifiers\n"));
                     return EXIT_FAILURE;
                   }
                   break;

   #ifdef AK_HAVE_BZLIB_H
        case 'j' : /* устанавливаем флаг сжатия перед шифрованием */
                   ki.compress_bz2 = ak_true;
                   break;
   #endif
		   
      /* устанавливаем имя генератора ключевой информации */
        case 205: /* --random */
                   if(( ki.oid_of_generator = ak_oid_find_by_ni( optarg )) == NULL ) {
                     aktool_error(
                        _("using unsupported name or identifier \"%s\" for random generator"),
                                                                                          optarg );
                     printf(
                        _("try \"aktool s --oid random\" for list of all available algorithms\n"));
                     return EXIT_FAILURE;
                   }
                   if(( ki.oid_of_generator->engine != random_generator ) ||
                                                     ( ki.oid_of_generator->mode != algorithm )) {
                     aktool_error(_("%s is not valid identifier for random generator"), optarg );
                     printf(
                       _("try \"aktool s --oid random\" for list of all available algorithms\n"));
                     return EXIT_FAILURE;
                   }
                   break;

      /* устанавливаем имя файла для генератора ключевой информации */
        case 206: /* --random-file */
                   ki.name_of_file_for_generator = optarg;
                   break;

      /* устанавливаем имена файлов (в полном, развернутом виде) */
        case 'o': /* -o, --output */
                  #ifdef _WIN32
                   GetFullPathName( optarg, FILENAME_MAX, ki.os_file, NULL );
                  #else
                   realpath( optarg , ki.os_file );
                  #endif
                   break;

      /* устанавливаем способы разбиения зашифровываемых файлов */
        case 231: /* --fs */
                   ki.heset.fraction.mechanism = size_fraction;
                   size_value = atoi( optarg );
                   if(( strchr( optarg, 'k' ) != NULL ) ||
                      ( strchr( optarg, 'K' ) != NULL )) size_value *= 1024;
                   if(( strchr( optarg, 'm' ) != NULL ) ||
                      ( strchr( optarg, 'M' ) != NULL )) size_value *= 1048576;
                                                               /* константа из ak_options.c */
                   ki.heset.fraction.value = ak_max( 4096, ak_min( size_value, 2147483648 ));
                   break;

        case 232: /* --fc */
                   ki.heset.fraction.mechanism = count_fraction;
                   ki.heset.fraction.value = ak_max( 1, atoi( optarg ));
                   break;

        case 233: /* --fr */
                   ki.heset.fraction.mechanism = random_size_fraction;
                   ki.heset.fraction.value = 10;
                   break;

        default:  /* обрабатываем ошибочные параметры */
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
       if(( ki.generator = aktool_key_new_generator()) == NULL ) {
        aktool_error(_("incorrect creation of random sequences generator"));
        exitcode = EXIT_FAILURE;
       }
        else {
               ak_random gptr = ki.generator;
               exitcode = aktool_encrypt_work( argc, argv );
               ak_ptr_wipe( &ki, sizeof( aktool_ki_t ), gptr );
               aktool_key_delete_generator( gptr );
             }
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
 typedef struct {
  int errcount;
 } handle_ptr_t;

/* ----------------------------------------------------------------------------------------------- */
 static int aktool_encrypt_function( const char *filename, ak_pointer ptr )
{
  struct file file;
  handle_ptr_t *st = ptr;
  char *name = (char *)filename;

 /* проверяем наличие файла */
  if( ak_file_open_to_read( &file, filename ) != ak_error_ok ) {
    if( st!= NULL ) st->errcount++;
    aktool_error(_("incorrect reading a file %s (%s)"), filename, strerror( errno ));
    return ak_error_access_file;
  }

 /* архивируем файл перед зашифрованием */
 #ifdef AK_HAVE_BZLIB_H
  if( ki.compress_bz2 ) {
    size_t val = 1;
    char buffer[4096];
    BZFILE *fz = NULL;
    char newname[FILENAME_MAX];

    ak_snprintf( newname, sizeof( newname ), "%s.bz2", filename );
    name = newname;

    if(( fz = BZ2_bzopen( newname, "wb" )) == NULL ) {
      if( st!= NULL ) st->errcount++;
      ak_file_close( &file );
      aktool_error(_("incorrect creation of archive file (%s)"), strerror( errno ));
      return ak_error_create_file;
    }

    while(( val = ak_file_read( &file, buffer, sizeof( buffer ))) != 0 ) {
      BZ2_bzwrite( fz, buffer, val );
    }
    BZ2_bzclose ( fz );
  }
 #endif
  ak_file_close( &file );

  ak_hybrid_encrypt_file( &ki.heset, NULL,
      name, ki.os_file, 
     /* если имя не задано, то формируем новое */
      strlen( ki.os_file ) > 0 ? 0 : sizeof( ki.os_file ), 
      ki.generator, NULL, 0 );
  memset( ki.os_file, 0, strlen( ki.os_file ));
 
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_encrypt_work( int argc, tchar *argv[] )
{
   int errcount = 0;
   handle_ptr_t st = { .errcount = 0 };

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
     st.errcount = 0;
     switch( ak_file_or_directory( value )) {
        case DT_DIR:
          if( ak_file_find( value, ki.pattern,
                            aktool_encrypt_function, &st, ki.tree ) != ak_error_ok )
                                                                           errcount += st.errcount;
          break;

        case DT_REG: if( aktool_encrypt_function( value, &st ) != ak_error_ok ) errcount++;
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
     "     --fc                set the number of fragments into which the input file will be splitted\n"
     "     --fs                set the length of one fragment\n"
     "     --fr                use fragments of random length when splitting the input file\n"
  ));
   #ifdef AK_HAVE_BZLIB_H
  printf(
   _(" -j, --bz2               compress the file before encryption\n"
  ));
   #endif
  printf(
   _(" -m, --mode              set the authenticated encryption mode [ default value: \"%s\" ]\n"
     " -o, --output            set the name of encrypted file\n"
     " -p, --pattern           set the pattern which is used to find files\n"
     "     --random            set the name or identifier of random sequences generator\n"
     "                         the generator will be used in ephermal keys generation [ default value: \"%s\" ]\n"
     "     --random-file       set the name of file with random sequence\n"
     " -r, --recursive         recursive search of files\n"
  ), ki.heset.mode->name[0], aktool_default_generator );

 return aktool_print_common_options();
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                              aktool_encrypt.c   */
/* ----------------------------------------------------------------------------------------------- */

