/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2019 - 2022 by Axel Kenzo, axelkenzo@mail.ru                                     */
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
#ifdef AK_HAVE_UNISTD_H
 #include <unistd.h>
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
     { "key",                 1, NULL,  'k' },
     { "ckpass",              1, NULL,  201 },
     { "ckpass-hex",          1, NULL,  202 },
     { "ck",                  1, NULL,  203 },
     { "container-key",       1, NULL,  203 },
     { "random",              1, NULL,  205 },
     { "random-file",         1, NULL,  206 },
     { "keypass",             1, NULL,  210 },
     { "keypass-hex",         1, NULL,  211 },
     { "fs",                  1, NULL,  231 },
     { "fc",                  1, NULL,  232 },
     { "fr",                  0, NULL,  233 },
     { "cert",                1, NULL,  'c' },
     { "ca-cert",             1, NULL,  208 },
     { "outpass",             1, NULL,  248 },
     { "outpass-hex",         1, NULL,  249 },
     { "inpass-hex",          1, NULL,  251 },
     { "inpass",              1, NULL,  252 },
     { "delete-source",       0, NULL,  253 },

   #ifdef AK_HAVE_BZLIB_H
     { "bz2",                 0, NULL,  'j' },
   #endif
     
     aktool_common_functions_definition,
     { NULL,               0, NULL,   0  },
  };

 /* устанавливаем параметры программы в значения по-умолчанию */
  ki.method = ak_oid_find_by_name( "ecies-scheme-key" );
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
  ki.heset.scheme = ecies_scheme;
  ki.delete_source = ak_false;

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "hp:rjo:m:c:k:", long_options, NULL );
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

        case 208: /* --ca-cert */
                  #ifdef _WIN32
                    GetFullPathName( optarg, FILENAME_MAX, ki.capubkey_file, NULL );
                  #else
                    realpath( optarg , ki.capubkey_file );
                  #endif
                    break;
        case 'c': /* -c --cert */
                  #ifdef _WIN32
                    GetFullPathName( optarg, FILENAME_MAX, ki.pubkey_file, NULL );
                  #else
                    realpath( optarg , ki.pubkey_file );
                  #endif
                    break;

        case 248: /* --outpass */
                   memset( ki.outpass, 0, sizeof( ki.outpass ));
                   strncpy( ki.outpass, optarg, sizeof( ki.outpass ) -1 );
                   if(( ki.lenoutpass = strlen( ki.outpass )) == 0 ) {
                     aktool_error(_("the password cannot be zero length, see --outpass option"));
                     return EXIT_FAILURE;
                   }
                   break;

        case 252: /* --inpass */
                   memset( ki.inpass, 0, sizeof( ki.inpass ));
                   strncpy( ki.inpass, optarg, sizeof( ki.inpass ) -1 );
                   if(( ki.leninpass = strlen( ki.inpass )) == 0 ) {
                     aktool_error(_("the password cannot be zero length, see --inpass option"));
                     return EXIT_FAILURE;
                   }
                   break;

        case 201: /* --ckpass */
                   memset( ki.ckpass, 0, sizeof( ki.ckpass ));
                   strncpy( ki.ckpass, optarg, sizeof( ki.ckpass ) -1 );
                   if(( ki.lenckpass = strlen( ki.ckpass )) == 0 ) {
                     aktool_error(_("the password cannot be zero length, see --ckpass option"));
                     return EXIT_FAILURE;
                   }
                   break;

        case 210: /* --keypass */
                   memset( ki.keypass, 0, sizeof( ki.keypass ));
                   strncpy( ki.keypass, optarg, sizeof( ki.keypass ) -1 );
                   if(( ki.lenkeypass = strlen( ki.keypass )) == 0 ) {
                     aktool_error(_("the password cannot be zero length, see --keypass option"));
                     return EXIT_FAILURE;
                   }
                   break;

      /* передача паролей через командную строку в шестнадцатеричном виде */
        case 249: /* --outpass-hex */
                   ki.lenoutpass = 0;
                   memset( ki.outpass, 0, sizeof( ki.outpass ));
                   if( ak_hexstr_to_ptr( optarg, ki.outpass,
                                              sizeof( ki.outpass ), ak_false ) == ak_error_ok ) {
                     ki.lenoutpass = ak_min(( strlen( optarg )%2 ) + ( strlen( optarg ) >> 1 ),
                                                                             sizeof( ki.outpass ));
                   }
                   if( ki.lenoutpass == 0 ) {
                       aktool_error(_("the password cannot be zero length, "
                                                   "maybe input error, see --outpass-hex %s%s%s"),
                                  ak_error_get_start_string(), optarg, ak_error_get_end_string( ));
                       return EXIT_FAILURE;
                     }
                   break;

        case 251: /* --inpass-hex */
                   ki.leninpass = 0;
                   memset( ki.inpass, 0, sizeof( ki.inpass ));
                   if( ak_hexstr_to_ptr( optarg, ki.inpass,
                                                sizeof( ki.inpass ), ak_false ) == ak_error_ok ) {
                     ki.leninpass = ak_min(( strlen( optarg )%2 ) + ( strlen( optarg ) >> 1 ),
                                                                              sizeof( ki.inpass ));
                   }
                   if( ki.leninpass == 0 ) {
                       aktool_error(_("the password cannot be zero length, "
                                                    "maybe input error, see --inpass-hex %s%s%s"),
                                  ak_error_get_start_string(), optarg, ak_error_get_end_string( ));
                       return EXIT_FAILURE;
                     }
                   break;

        case 202: /* --ckpass-hex */
                   ki.lenckpass = 0;
                   memset( ki.ckpass, 0, sizeof( ki.ckpass ));
                   if( ak_hexstr_to_ptr( optarg, ki.ckpass,
                                                sizeof( ki.ckpass ), ak_false ) == ak_error_ok ) {
                     ki.lenckpass = ak_min(( strlen( optarg )%2 ) + ( strlen( optarg ) >> 1 ),
                                                                              sizeof( ki.ckpass ));
                   }
                   if( ki.lenckpass == 0 ) {
                       aktool_error(_("the password cannot be zero length, "
                                                    "maybe input error, see --ckpass-hex %s%s%s"),
                                  ak_error_get_start_string(), optarg, ak_error_get_end_string( ));
                       return EXIT_FAILURE;
                     }
                   break;

        case 211: /* --keypass-hex */
                   ki.lenkeypass = 0;
                   memset( ki.keypass, 0, sizeof( ki.keypass ));
                   if( ak_hexstr_to_ptr( optarg, ki.keypass,
                                               sizeof( ki.keypass ), ak_false ) == ak_error_ok ) {
                     ki.lenkeypass = ak_min(( strlen( optarg )%2 ) + ( strlen( optarg ) >> 1 ),
                                                                             sizeof( ki.keypass ));
                   }
                   if( ki.lenkeypass == 0 ) {
                       aktool_error(_("the password cannot be zero length, "
                                                    "maybe input error, see --keypass-hex %s%s%s"),
                                  ak_error_get_start_string(), optarg, ak_error_get_end_string( ));
                       return EXIT_FAILURE;
                     }
                   break;

        case 'k': /* --key, -k */
                  #ifdef _WIN32
                    GetFullPathName( optarg, FILENAME_MAX, ki.key_file, NULL );
                  #else
                    realpath( optarg , ki.key_file );
                  #endif
                   break;

        case 203: /* --container-key, --ck */
                  #ifdef _WIN32
                    GetFullPathName( optarg, FILENAME_MAX, ki.op_file, NULL );
                  #else
                    realpath( optarg , ki.op_file );
                  #endif
                   break;

        case 253: /* --delete-source */
                   ki.delete_source = ak_true;
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
 typedef struct {
   int errcount;
   ak_ecies_scheme sheme;
   ak_pointer key;
 } handle_ptr_t;

/* ----------------------------------------------------------------------------------------------- */
 static int aktool_encrypt_function( const char *filename, ak_pointer ptr )
{
  struct file file;
  handle_ptr_t *st = ptr;
  int error = ak_error_ok;
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
    size_t val = 1, sum = 0;
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
      if( (sum += val )%1048576U == 0 ) {
        if( !ki.quiet ) {
          fprintf( stdout, _("%s (Compression ... %3luMb)%s"), filename, sum>>20, "\r" ); fflush( stdout );
        }
      }
    }
    BZ2_bzclose ( fz );
  }
 #endif
  ak_file_close( &file );

  if( st->key != NULL )  {
     error = ak_encrypt_file_with_key( name,
                   &ki.heset,
                   st->sheme,
                   ki.os_file,
                 /* если имя не задано, то формируем новое */
                   strlen( ki.os_file ) > 0 ? 0 : sizeof( ki.os_file ),
                   ki.generator,
                   (ak_skey)st->key
     );
  }
   else {
     error = ak_encrypt_file( name,
                   &ki.heset,
                   st->sheme,
                   ki.os_file,
                 /* если имя не задано, то формируем новое */
                   strlen( ki.os_file ) > 0 ? 0 : sizeof( ki.os_file ),
                   ki.generator,
                   ki.outpass,
                   ki.lenoutpass
     );
   }

 /* удаляем архивированный файл */
 #ifdef AK_HAVE_BZLIB_H
  if( ki.compress_bz2 ) {
    #ifdef AK_HAVE_UNISTD_H
     unlink(name);
    #else
     remove(name);
    #endif
  }
 #endif

  if( error == ak_error_ok ) {
   /* удаляем файл с исходными (открытыми) данными */
    if( ki.delete_source ) {
      #ifdef AK_HAVE_UNISTD_H
       unlink( filename );
      #else
       remove( filename );
      #endif
    }
    fprintf( stdout, "%s (%s): Ok\n", filename, ki.os_file );
  }
   else aktool_error("%s (wrong encryption)", filename );

 /* очищаем имя зашифрованного файла
   (для предотвращения попыток записи нескольких файлов в один) */
  memset( ki.os_file, 0, strlen( ki.os_file ));

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 static ssize_t aktool_set_ckpass( const char *prompt, char *password,
                                                           const size_t pass_size, password_t hex )
{
  memset( password, 0, pass_size );
  if( ki.lenckpass > 0 ) {
    memcpy( password, ki.ckpass, ak_min( (size_t)ki.lenckpass, pass_size ));
  }
  return ki.lenckpass;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_encrypt_work( int argc, tchar *argv[] )
{
   ak_random gptr = NULL;
   struct ecies_scheme subject;
   int errcount = 0, exitcode = EXIT_SUCCESS;
   struct certificate issuer, *issuer_ptr = NULL;
   handle_ptr_t st = { .errcount = 0, .sheme = &subject, .key = NULL };

 /* в начале, пропускаем команду - e или encrypt */
   ++optind;
   if( optind >= argc ) {
     aktool_error(_("the name of file or directory is not specified as the argument of the program"));
     return EXIT_FAILURE;
   }

 /* создаем генератор случайных чисел */
   if(( ki.generator = aktool_key_new_generator()) == NULL ) {
     aktool_error(_("incorrect creation of random sequences generator"));
     return EXIT_FAILURE;
   }

 /* проверяем наличие ключа шифрования */
   if( strlen( ki.pubkey_file ) == 0 ) {
     aktool_error(_("the recipient's public key certificate is not defined, use \"--cert\" option"));
     exitcode = EXIT_FAILURE;
     goto lab_exit;
   }

 /* считываем сертификат открытого ключа издателя сертификата (если он указан в командной строке) */
   if( strlen( ki.capubkey_file ) != 0 ) {
     if( ak_certificate_import_from_file( &issuer, NULL, ki.capubkey_file ) != ak_error_ok ) {
       aktool_error(_("incorrect reading of CA certificate (see --ca-cert option)"));
       exitcode = EXIT_FAILURE;
       goto lab_exit;
     }
      else issuer_ptr = &issuer;
   }

 /* считываем сертификат открытого ключа получателя сообщения */
   if( ak_certificate_import_from_file( &subject.recipient, issuer_ptr, ki.pubkey_file ) != ak_error_ok ) {
     aktool_error(_("incorrect reading of recipient's public key certificate (see --cert and --ca-cert options)"));
     exitcode = EXIT_FAILURE;
     goto lab_exit;
   }

 /* если задана опция --container-key, то используем указанный секретный ключ для шифрования контейнера
    в противном случае используем пароль (из командной строки или заданный пользователем) */
   if( strlen( ki.op_file ) != 0 ) {
     if( ki.lenckpass != 0 ) {
       /* подменяем функцию ввода пароля доступа к секретному ключу */
       ak_libakrypt_set_password_read_function( aktool_set_ckpass );
     }
      else printf(_("Loading a secret key to access the file container,\nset the access "));
     if(( st.key = ak_skey_load_from_file( ki.op_file )) == NULL ) {
       aktool_error(_("incorrect access to the secret key file (see --container-key or --ckpass options)"));
       exitcode = EXIT_FAILURE;
       goto lab_exit2;
     }
    /* возвращаем функцию ввода пароля доступа к секретному ключу в исходное состояние */
     ak_libakrypt_set_password_read_function( ak_password_read_from_terminal );
   }
    else { /* проверяем, задан ли пароль шифрования контейнера */
      if( ki.lenoutpass == 0 ) {
        if( !ki.quiet ) printf(_("Specify the password to access the encrypted file container.\n"
                            "This will not distinguish the encrypted file from a random data.\n"));
        if(( ki.lenoutpass =
                       aktool_load_user_password_twice( ki.outpass, sizeof( ki.outpass ))) < 1 ) {
          exitcode = EXIT_FAILURE;
          goto lab_exit2;
        }
      }
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

 /* проверяем на наличие ошибок при шифровании */
   if( errcount ) {
     if( !ki.quiet ) aktool_error(_("aktool found %d error(s), "
            "rerun aktool with \"--audit-file stderr\" option or see syslog messages"), errcount );
     exitcode = EXIT_FAILURE;
   }

 /* очищаем память и удаляем генератор случайных чисел */
   if( st.key != NULL ) ak_oid_delete_object( ((ak_skey)st.key)->oid , st.key );

 lab_exit2:
   ak_certificate_destroy( &subject.recipient );

 lab_exit:
   if( issuer_ptr != NULL ) ak_certificate_destroy( issuer_ptr );

   gptr = ki.generator;
   ak_ptr_wipe( &ki, sizeof( aktool_ki_t ), gptr );
   aktool_key_delete_generator( gptr );

 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
/*                          Реализация процедуры расшифрования файла                               */
/* ----------------------------------------------------------------------------------------------- */
 static ssize_t aktool_set_keypass( const char *prompt, char *password,
                                                           const size_t pass_size, password_t hex )
{
  memset( password, 0, pass_size );
  if( ki.lenkeypass > 0 ) {
    memcpy( password, ki.keypass, ak_min( (size_t)ki.lenkeypass, pass_size ));
  }
  return ki.lenkeypass;
}

/* ----------------------------------------------------------------------------------------------- */
 static int aktool_decrypt_function( const char *filename, ak_pointer ptr )
{
  int error= ak_error_ok;
  handle_ptr_t *st = ptr;

  if( ki.lenkeypass != 0 ) { /* подменяем функцию ввода пароля доступа к секретному ключу */
    ak_libakrypt_set_password_read_function( aktool_set_keypass );
  }
  if( st->key != NULL )  {
    error = ak_decrypt_file_with_key(
              filename,
              (ak_skey)st->key,
              strlen( ki.key_file ) > 0 ? ki.key_file : NULL,
              ki.os_file,
              strlen( ki.os_file ) > 0 ? 0 : sizeof( ki.os_file )
            );
  } else {
     error = ak_decrypt_file(
               filename,
               ki.inpass,
               ki.leninpass,
               strlen( ki.key_file ) > 0 ? ki.key_file : NULL,
               ki.os_file,
               strlen( ki.os_file ) > 0 ? 0 : sizeof( ki.os_file )
             );
   }
  ak_libakrypt_set_password_read_function( ak_password_read_from_terminal );

 /* в случае успеха, выполняем дополнительный функционал */
  if( error == ak_error_ok ) {

    /* 1. не забываем про разархивирование расшифрованных данных */
     #ifdef AK_HAVE_BZLIB_H
     if( strstr( ki.os_file, ".bz2" ) != NULL ) {
       char command[1024];
       memset( command, 0, sizeof( command ));
       ak_snprintf( command, sizeof( command ) -1, "bunzip2 -f %s", ki.os_file );
       system( command );
       ki.os_file[ strlen( ki.os_file ) -4 ] = 0;
     }
     #endif

    /* 2. удаляем файл с исходными (зашифрованными) данными */
     if( ki.delete_source ) {
       #ifdef AK_HAVE_UNISTD_H
        unlink( filename );
       #else
        remove( filename );
       #endif
     }

     if( !ki.quiet ) fprintf( stdout, "%s (%s): Ok\n", filename, ki.os_file );
  }
   else {
    st->errcount++;
    aktool_error("%s (wrong decryption)", filename );
   }

 /* очищаем имя выходного файла, чтобы не расшифровывать два файла в один */
  memset( ki.os_file, 0, sizeof( ki.os_file ));

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_decrypt_work( int argc, tchar *argv[] )
{
   int errcount = 0, exitcode = EXIT_SUCCESS;
   handle_ptr_t st = { .errcount = 0, .sheme = NULL, .key = NULL };

 /* в начале, пропускаем команду - d или decrypt */
   ++optind;
   if( optind >= argc ) {
     aktool_error(_("the name of file or directory is not specified as the argument of the program"));
     return EXIT_FAILURE;
   }

 /* если задана опция --container-key, то используем указанный секретный ключ для шифрования контейнера
    в противном случае используем пароль (из командной строки или заданный пользователем) */
   if( strlen( ki.op_file ) != 0 ) {
     if( ki.lenckpass != 0 ) {
       /* подменяем функцию ввода пароля доступа к секретному ключу */
       ak_libakrypt_set_password_read_function( aktool_set_ckpass );
     }
      else printf(_("Loading a secret key to access the file container,\nset the access "));
     if(( st.key = ak_skey_load_from_file( ki.op_file )) == NULL ) {
       aktool_error(_("incorrect access to the secret key file (see --container-key or --ckpass options)"));
       exitcode = EXIT_FAILURE;
       goto lab_exit2;
     }
    /* возвращаем функцию ввода пароля доступа к секретному ключу в исходное состояние */
     ak_libakrypt_set_password_read_function( ak_password_read_from_terminal );
   }
    else { /* проверяем, задан ли пароль шифрования контейнера */

       if( ki.leninpass == 0 ) {
         if( !ki.quiet ) printf(_("You must specify a password to access the file container\n"));
         if(( ki.leninpass = aktool_load_user_password( NULL, ki.inpass, sizeof( ki.inpass ), 0 )) < 1 ) {
           aktool_error(_("incorrect password reading"));
           exitcode = EXIT_FAILURE;
           goto lab_exit2;
         }
       }
    }

 /* основной перебор заданных пользователем файлов и каталогов */
   while( optind < argc ) {
     char *value = argv[optind++];
     st.errcount = 0;
     switch( ak_file_or_directory( value )) {
        case DT_DIR:
          if( ak_file_find( value, ki.pattern,
                            aktool_decrypt_function, &st, ki.tree ) != ak_error_ok )
                                                                           errcount += st.errcount;
          break;

        case DT_REG: if( aktool_decrypt_function( value, &st ) != ak_error_ok ) errcount++;
          break;

        default: aktool_error(_("%s is unsupported argument"), value ); errcount++;
          break;
     }
   }

  lab_exit2:
 /* очищаем память и удаляем генератор случайных чисел */
   if( st.key != NULL ) ak_oid_delete_object( ((ak_skey)st.key)->oid , st.key );

 /* проверяем на наличие ошибок при шифровании */
   if( errcount ) {
     if( !ki.quiet ) aktool_error(_("aktool found %d error(s), "
            "rerun aktool with \"--audit-file stderr\" option or see syslog messages"), errcount );
     exitcode = EXIT_FAILURE;
   }

 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                             вывод справки                                       */
/* ----------------------------------------------------------------------------------------------- */
 int aktool_encrypt_help( void )
{
  printf(
   _("aktool encrypt/decrypt [options] [files or directories] - file encryption and decryption features\n\n"
     "available options:\n"
     "     --ca-cert           set the file with certificate of authorithy's public key\n"
     " -c  --cert              the recipient's public key certificate\n"
     "     --ck                short form for the --container-key option\n"
     "     --ckpass            set the password for access key directly in command line\n"
     "     --ckpass-hex        set the password for access key as hexademal string\n"
     "     --container-key     specify the secret key for access to the file container\n"
     "                         this is stronger than applying a password, but does not override the use of a public key\n"
     "     --delete-source     delete the encrypted or decrypted file\n"
     "     --fc                set the number of fragments into which the input file will be splitted\n"
     "     --fr                use fragments of random length when splitting the input file\n"
     "     --fs                set the length of one fragment\n"
     "     --inpass            set the password for decrypting one or more files directly in command line\n"
     "     --inpass-hex        set the password for decrypting files as hexademal string\n"
  ));
   #ifdef AK_HAVE_BZLIB_H
  printf(
   _(" -j, --bz2               compress the file before encryption\n"
  ));
   #endif
  printf(
   _(" -k, --key               set the file with secret decryption key\n"
     "     --keypass           set the password for secret decryption key directly in command line\n"
     "     --keypass-hex       set the password for secret decryption key as hexademal string\n"
     " -m, --mode              set the authenticated encryption mode [ default value: \"%s\" ]\n"
     "     --outpass           set the password for the encrypting one or more files directly in command line\n"
     "     --outpass-hex       set the password for the encrypting files as hexademal string\n"
     " -o, --output            set the name of encrypted file\n"
     " -p, --pattern           set the pattern which is used to find files\n"
     "     --random            set the name or identifier of random sequences generator\n"
     "                         the generator will be used for ephermal keys generation [ default value: \"%s\" ]\n"
     "     --random-file       set the name of file with random sequence\n"
     " -r, --recursive         recursive search of files\n"
  ), ki.heset.mode->name[0], aktool_default_generator );
  aktool_print_common_options();

  printf(_("for usage examples try \"man aktool\"\n" ));

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                              aktool_encrypt.c   */
/* ----------------------------------------------------------------------------------------------- */

