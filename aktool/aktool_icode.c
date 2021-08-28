/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 - 2021 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Прикладной модуль, реализующий процедуры проверки целостности данных                           */
/*                                                                                                 */
/*  aktool_ikey.c                                                                                  */
/* ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <aktool.h>
#ifdef AK_HAVE_ERRNO_H
 #include <errno.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_help( void );
 int aktool_icode_work( int argc, tchar *argv[] );

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode( int argc, tchar *argv[] )
{
  int next_option = 0, exit_status = EXIT_FAILURE;
  enum { do_nothing, do_hash, do_check } work = do_hash;

  const struct option long_options[] = {
   /* сначала уникальные */
     { "algorithm",           1, NULL,  'a' },
     { "pattern",             1, NULL,  'p' },
     { "output",              1, NULL,  'o' },
     { "recursive",           0, NULL,  'r' },
     { "reverse-order",       0, NULL,  254 },
     { "seed",                1, NULL,  253 },
     { "tag",                 0, NULL,  250 },
     { "mode",                1, NULL,  'm' },
     { "no-derive",           0, NULL,  160 },

    /* аналоги из aktool_key */
     { "key",                 1, NULL,  203 },
     { "inpass-hex",          1, NULL,  251 },
     { "inpass",              1, NULL,  252 },

   /* это стандартые для всех программ опции */
     aktool_common_functions_definition,
     { NULL,                  0, NULL,   0  },
  };

 /* устанавливаем значения по-умолчанию */
  ki.method = ak_oid_find_by_name( "streebog256" );
  ki.mode = NULL;
  ki.outfp = NULL;
  ki.pattern =
  #ifdef _WIN32
   "*.*";
  #else
   "*";
  #endif
  ki.tree = ak_false;
  ki.outfp = stdout;
  ki.seed = NULL;
  ki.key_derive = ak_true;

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "ha:p:ro:m:", long_options, NULL );
       switch( next_option )
      {
        aktool_common_functions_run( aktool_icode_help );

        case 'a': /* --algorithm  устанавливаем имя криптографического алгоритма */
                   if(( ki.method = ak_oid_find_by_ni( optarg )) == NULL ) {
                     aktool_error(_("using unsupported name or identifier \"%s\""), optarg );
                     printf(_("try \"aktool s --oids\" for list of all available identifiers\n"));
                     return EXIT_FAILURE;
                   }
                   break;

        case 'm': /* --mode  устанавливаем режим использования криптографического алгоритма */
                   if(( ki.mode = ak_oid_find_by_ni( optarg )) == NULL ) {
                     aktool_error(_("using unsupported name or identifier \"%s\""), optarg );
                     printf(_("try \"aktool s --oids\" for list of all available identifiers\n"));
                     return EXIT_FAILURE;
                   }
                   if( ki.mode->engine != block_cipher ) {
                     aktool_error(_("you must use the block cipher mode as an argument to the --mode option"));
                     printf(_("try \"aktool s --oid cipher\" for list of all available identifiers\n"));
                     return EXIT_FAILURE;
                   }
                   switch( ki.mode->mode ) {
                     case mac: /* здесь перечисляются допустимые режимы выработки имитовставки */
                       break;
                     default:
                       aktool_error(_("you must use authentication mode for block cipher"));
                       return EXIT_FAILURE;
                   }
                   break;

        case 'o' : /* устанавливаем имя файла для вывода результатов */
                 #ifdef _WIN32
                   GetFullPathName( optarg, FILENAME_MAX, ki.op_file, NULL );
                 #else
                   realpath( optarg , ki.op_file );
                 #endif
                   if(( ki.outfp = fopen( optarg, "w" )) == NULL ) {
                     aktool_error(_("checksum file \"%s\" cannot be created"), optarg );
                     return EXIT_FAILURE;
                   }
                   break;

        case 'p' : /* устанавливаем дополнительную маску для поиска файлов */
                   ki.pattern = optarg;
                   break;

        case 'r' : /* устанавливаем флаг рекурсивного обхода каталогов */
                   ki.tree = ak_true;
                   break;

        case 254 : /* --reverse-order установить обратный порядок вывода байт */
                   ki.reverse_order = ak_true;
                   break;

        case 250 : /* --tag вывод в стиле BSD */
                   ki.tag = ak_true;
                   break;

        case 253: /* --seed */
                   ki.seed = optarg;
                   break;

        case 160: /* --no-derive */
                   ki.key_derive = ak_false;
                   break;

        case 252: /* --inpass */
                   memset( ki.inpass, 0, sizeof( ki.inpass ));
                   strncpy( ki.inpass, optarg, sizeof( ki.inpass ) -1 );
                   if(( ki.leninpass = strlen( ki.inpass )) == 0 ) {
                     aktool_error(_("the password cannot be zero length"));
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

        case 203: /* --key, --ca-key */
                  #ifdef _WIN32
                    GetFullPathName( optarg, FILENAME_MAX, ki.key_file, NULL );
                  #else
                    realpath( optarg , ki.key_file );
                  #endif
                    break;

        default:  /* обрабатываем ошибочные параметры */
                   if( next_option != -1 ) work = do_nothing;
                   break;
       }

   } while( next_option != -1 );
   if( work == do_nothing ) return aktool_icode_help();

 /* начинаем работу с криптографическими примитивами */
   if( !aktool_create_libakrypt( )) return EXIT_FAILURE;

 /* теперь вызов соответствующей функции */
   switch( work ) {
     case do_hash:
       exit_status = aktool_icode_work( argc,  argv );
       break;

     case do_check:
       break;

     default:
       exit_status = EXIT_FAILURE;
   }

   if( ki.outfp != NULL ) fclose( ki.outfp );
   aktool_destroy_libakrypt();

 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
/*                    Реализация общего алгоритма обработки входных файлов                         */
/* ----------------------------------------------------------------------------------------------- */
 typedef int ( ak_function_icode_file ) ( ak_pointer , const char * , ak_pointer , const size_t );
 typedef struct {
  ak_pointer handle;
  ak_oid oid;
  size_t tagsize;
  ak_function_icode_file *icode;
  int errcount;
 } handle_ptr_t;

/* ----------------------------------------------------------------------------------------------- */
 static int aktool_icode_function( const char *filename, ak_pointer ptr )
{
  handle_ptr_t *st = ptr;
  ak_uint8 buffer[256];
  ak_pointer kh = NULL;
  int error = ak_error_ok;
  char flongname[FILENAME_MAX];

 /* проверяем размер доступной памяти для вычисления имитовставки */
  if( sizeof( buffer ) < st->tagsize ) {
    st->errcount++;
    return ak_error_wrong_length;
  }

 /* файл для вывода результатов не хешируем */
  if( ki.outfp != stdout ) {
    memset( flongname, 0, sizeof( flongname ));
   #ifdef _WIN32
    GetFullPathName( filename, FILENAME_MAX, flongname, NULL );
   #else
    realpath( filename, flongname );
   #endif
    if( !strncmp( flongname, ki.op_file, FILENAME_MAX -2 )) return ak_error_ok;
    if( !strncmp( flongname, ki.audit_filename,
                                              sizeof( ki.audit_filename ) -2 )) return ak_error_ok;
  }

 /* вырабатываем производный ключ (если пользователь не запретил) */
  if( !ki.key_derive || st->oid->engine == hash_function ) {
    kh = st->handle;
  }
   else {
    if(( kh = ak_skey_new_derive_kdf256( st->oid, st->handle,
                                           (ak_uint8 *)filename, strlen( filename ),
                                            ki.seed != NULL ? (ak_uint8 *)ki.seed : NULL,
                                            ki.seed != NULL ? strlen( ki.seed ) : 0 )) == NULL ) {
      aktool_error(_("incorrect creation of derivative key for %s"), filename );
      st->errcount++;
      return ak_error_get_value();
    }
  }

 /* проверяем ресурс секретного ключа */
  if( st->oid->engine == block_cipher ) {
    struct file fs;
    if(( error = ak_file_open_to_read( &fs, filename )) != ak_error_ok ) {
      aktool_error(_("access error to %s [%s]"), filename, strerror( errno ));
      st->errcount++;
      goto labex;
    }
    if( ((ak_bckey)kh)->key.resource.value.counter < (ssize_t)(1 + fs.size/st->tagsize )) {
      st->errcount++;
      aktool_error(_("low key resource for %s (%lld bytes)"), filename, fs.size );
      error = ak_error_low_key_resource;
    }
    ak_file_close( &fs );
    if( error != ak_error_ok ) goto labex;
  }

 /* хешируем */
  if(( error = st->icode( kh, /* производный ключ */
                              filename, buffer, st->tagsize )) != ak_error_ok ) {
    aktool_error(_("incorrect integrity code calculation for %s"), filename );
    st->errcount++;
    return error;
  }

 /* теперь вывод результата */
  if( ki.tag ) { /* вывод bsd */
    fprintf( ki.outfp, "%s (%s) = %s\n", st->oid->name[0], filename,
                                       ak_ptr_to_hexstr( buffer, st->tagsize, ki.reverse_order ));
  } else { /* вывод линуксовый */
      fprintf( ki.outfp, "%s %s\n",
                            ak_ptr_to_hexstr( buffer, st->tagsize, ki.reverse_order ), filename );
    }

  labex:
   if( kh != st->handle ) ak_oid_delete_object( st->oid, kh );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_work( int argc, tchar *argv[] )
{
   handle_ptr_t st;
   int errcount = 0;

  /* проверяем, что файлы для контроля заданы */
   ++optind; /* пропускаем команду - i или icode */
   if( optind >= argc ) {
     aktool_error(_(
                 "the name of file or directory is not specified as the argument of the program"));
     return EXIT_FAILURE;
   }

   if( strlen( ki.key_file ) != 0 ) {
     ak_libakrypt_set_password_read_function( aktool_load_user_password );
     if(( st.handle = ak_skey_load_from_file( ki.key_file )) == NULL ) {
       if( !ki.quiet ) aktool_error(_("wrong reading a secret key from %s file"), ki.key_file );
       return EXIT_FAILURE;
     }
     st.oid = ((ak_skey) st.handle)->oid;
     switch( st.oid->engine ) {
       case hmac_function:
         st.icode = ( ak_function_icode_file *) ak_hmac_file;
         st.tagsize = ak_hmac_get_tag_size( st.handle );
         break;

       case block_cipher:
         if( ki.mode == NULL ) {
           aktool_error(_("you need specify the argument of --mode option"));
           if( st.handle != NULL ) ak_oid_delete_object( ki.method, st.handle );
           return EXIT_FAILURE;
         }
         switch( ki.mode->mode ) {
           case mac: /* здесь перечисляются допустимые режимы выработки имитовставки */
             st.icode = ( ak_function_icode_file *) ak_bckey_cmac_file;
             break;

           default:
             aktool_error(_("you must use authentication mode for block cipher"));
             return EXIT_FAILURE;
         }
         st.oid = ki.mode;
         st.tagsize = ((ak_bckey)st.handle)->bsize;
         break;

       default:
         ki.method = ((ak_skey)st.handle)->oid;
         aktool_error(_(
                "%s is not valid identifier for integrity checking algorithm (wrong engine: %s)"),
                            ki.method->name[0], ak_libakrypt_get_engine_name( ki.method->engine ));
         if( st.handle != NULL ) ak_oid_delete_object( ki.method, st.handle );
         return EXIT_FAILURE;
     }
   }
    else { /* ключ не определен, следовательно, создаем контекст алгоритма хеширования */
      if( ki.method->engine != hash_function ) {
        aktool_error(_("the --algorithm option argument should be the name of the hash function"));
        return EXIT_FAILURE;
      }
      if(( st.handle = ak_oid_new_object( ki.method )) == NULL ) {
        if( !ki.quiet ) aktool_error(_("wrong creation context for %s algorithm"),
                                                                              ki.method->name[0] );
        return EXIT_FAILURE;
      }
      st.icode = ( ak_function_icode_file *) ak_hash_file;
      st.tagsize = ak_hash_get_tag_size( st.handle );
      st.oid = ((ak_hash)st.handle)->oid;
    }
   st.errcount = 0;

  /* только сейчас начиаем основной цикл хеширования файлов и каталогов, указанных пользователем */
   while( optind < argc ) {
     char *value = argv[optind++];
     switch( ak_file_or_directory( value )) {
        case DT_DIR:
          st.errcount = 0;
          if( ak_file_find( value, ki.pattern,
                            aktool_icode_function, &st, ki.tree ) != ak_error_ok )
                                                                           errcount += st.errcount;
          break;

        case DT_REG: if( aktool_icode_function( value, &st )!= ak_error_ok ) errcount++;
          break;

        default: aktool_error(_("%s is unsupported argument"), value ); errcount++;
          break;
     }
   }

  /* освобождаем выделенную ранее память */
   if( st.handle != NULL ) {
     if( st.icode == (ak_function_icode_file *)ak_hash_file )
       ak_oid_delete_object( ((ak_hash)st.handle)->oid, st.handle );
      else ak_oid_delete_object( ((ak_skey)st.handle)->oid, st.handle );
   }
   if( errcount ) {
     if( !ki.quiet ) aktool_error(_("aktool found %d error(s), "
            "rerun aktool with \"--audit-file stderr\" option or see syslog messages"), errcount );
     return EXIT_FAILURE;
   }

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_icode_help( void )
{
  printf(
   _("aktool icode [options] [files or directories]  - calculate or checking integrity codes for given files\n\n"
     "available options:\n"
     " -a, --algorithm         set the name or identifier of integrity function (used only for integrity checking)\n"
     "                         default algorithm is \"streebog256\" defined by GOST R 34.10-2012\n"
     "     --inpass            set the password for the secret key to be read directly in command line\n"
     "     --inpass-hex        read the password for the secret key as hexademal string\n"
     "     --key               specify the name of file with the secret key\n"
     " -m, --mode              set the block cipher mode [enambled values: cmac]\n"
     "     --no-derive         do not use derived keys for file authentication\n"
     " -o, --output            set the output file for generated authentication or integrity codes\n"
     " -p, --pattern           set the pattern which is used to find files\n"
     " -r, --recursive         recursive search of files\n"
     "     --reverse-order     output of authentication or integrity code in reverse byte order\n"
     "     --seed              set the initial value of key derivation functions (used only for file authentication)\n"
     "     --tag               create a BSD-style checksum format\n"
  ));
  aktool_print_common_options();

  printf(_("for usage examples try \"man aktool\"\n" ));
 return EXIT_SUCCESS;
}
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 aktool_icode.c  */
/* ----------------------------------------------------------------------------------------------- */
