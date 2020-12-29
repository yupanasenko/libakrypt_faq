/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 - 2021 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Прикладной модуль, реализующий процедуры выработки ключевой информации,                        */
/*  используемой криптографическими алгоритмами библиотеки libakrypt                               */
/*                                                                                                 */
/*  aktool_key.c                                                                                   */
/* ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <aktool.h>

/* ----------------------------------------------------------------------------------------------- */
/* Предварительное описание используемых функций */
 int aktool_key_help( void );
 int aktool_key_new( void );
 int aktool_key_new_blom_master( void );
 int aktool_key_new_blom_subscriber( void );
 int aktool_key_new_blom_pairwise( void );
 int aktool_key_new_keypair( bool_t , bool_t );

#define aktool_magic_number (113)

/* ----------------------------------------------------------------------------------------------- */
 static struct key_info {
   ak_oid method;
   ak_oid oid_of_generator, oid_of_target;
   char *name_of_file_for_generator;
   export_format_t format;
   ak_oid curve;
   size_t days;
   ak_uint32 field, size;
   int verbose;
   int target_undefined;
   ssize_t lenpass, lenkeypass, lenuser;
   struct certificate_opts opts;
   char password[aktool_password_max_length];
   char key_password[aktool_password_max_length];
   char keylabel[256];
   char user[512]; /* идентификатор пользователя ключа */

   char os_file[FILENAME_MAX];   /* сохраняем, секретный ключ */
   char op_file[FILENAME_MAX];    /* сохраняем, открытый ключ */
   char key_file[FILENAME_MAX];     /* читаем, секретный ключ */
   char pubkey_file[FILENAME_MAX];   /* читаем, открытый ключ */
 } ki;

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key( int argc, char *argv[] )
{
  int next_option = 0, exit_status = EXIT_FAILURE;
  enum { do_nothing, do_new, do_cert } work = do_nothing;

 /* параметры, запрашиваемые пользователем */
  const struct option long_options[] = {
   /* сначала уникальные */
     { "algorithm",           1, NULL,  'a' },
     { "new",                 0, NULL,  'n' },
     { "output-secret-key",   1, NULL,  'o' },
     { "to",                  1, NULL,  250 },
     { "hexpass",             1, NULL,  249 },
     { "password",            1, NULL,  248 },
     { "key-hexpass",         1, NULL,  251 },
     { "key-password",        1, NULL,  252 },
     { "curve",               1, NULL,  247 },
     { "days",                1, NULL,  246 },

     { "pubkey",              1, NULL,  208 },
     { "label",               1, NULL,  207 },
     { "random-file",         1, NULL,  206 },
     { "random",              1, NULL,  205 },
     { "key",                 1, NULL,  203 },
     { "op",                  1, NULL,  202 },
     { "output-public-key",   1, NULL,  202 },

   /* флаги для генерации ключей схемы Блома */
     { "field",               1, NULL,  180 },
     { "size",                1, NULL,  181 },
     { "id",                  1, NULL,  182 },
     { "hexid",               1, NULL,  183 },
     { "target",              1, NULL,  't' },

    /* флаги использования открытого ключа */
     { "digital-signature",   0, NULL,  190 },
     { "content-commitment",  0, NULL,  191 },
     { "key-encipherment",    0, NULL,  192 },
     { "data-encipherment",   0, NULL,  193 },
     { "key-agreement",       0, NULL,  194 },
     { "key-cert-sign",       0, NULL,  195 },
     { "crl-sign",            0, NULL,  196 },
     { "ca",                  1, NULL,  197 },
     { "pathlen",             1, NULL,  198 },
     { "authority-keyid",     0, NULL,  199 },
     { "authority-name",      0, NULL,  200 },

     aktool_common_functions_definition,
     { NULL,                  0, NULL,   0  },
  };

 /* инициализируем множество параметров по-умолчанию */
  memset( &ki, 0, sizeof( struct key_info ));
  ki.method = NULL;
  ki.oid_of_target = NULL;
  ki.oid_of_generator = ak_oid_find_by_name( aktool_default_generator );
  ki.name_of_file_for_generator = NULL;
  ki.format = asn1_der_format;
  ki.curve = ak_oid_find_by_name( "id-tc26-gost-3410-2012-256-paramSetA" );
  ki.days = 365;
 /* параметры секретного ключа для схемы Блома */
  ki.field = ak_galois256_size;
  ki.size = 512;
  ki.verbose = ak_true;
 /*  далее ki состоит из одних нулей */

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "hna:o:t:", long_options, NULL );
       switch( next_option )
      {
        aktool_common_functions_run( aktool_key_help );

      /* управляющие команды */
        case 'n' :  work = do_new;
                    break;

      /* устанавливаем имя криптографического алгоритма генерации ключей */
        case 'a' :  if(( ki.method = ak_oid_find_by_ni( optarg )) == NULL ) {
                      aktool_error(_("using unsupported name or identifier \"%s\""), optarg );
                      printf(_("try \"aktool s --oids\" for list of all available identifiers\n"));
                     return EXIT_FAILURE;
                    }
                    if( ki.method->mode != algorithm ) {
                      aktool_error(_("%s is not valid identifier for algorithm"), optarg );
                      printf(
                     _("try \"aktool s --oid algorithm\" for list of all available algorithms\n"));
                      return EXIT_FAILURE;
                    }
                    break;

      /* устанавливаем имя криптографического алгоритма для которого вырабатывается ключ */
        case 't' : /* --target */
                   if( strncmp( optarg, "undefined", 9 ) == 0 ) {
                     ki.oid_of_target = NULL;
                     ki.target_undefined = ak_true;
                     break;
                   }
                   ki.target_undefined = ak_false;
                   if(( ki.oid_of_target = ak_oid_find_by_ni( optarg )) == NULL ) {
                      aktool_error(_("using unsupported name or identifier \"%s\""), optarg );
                      printf(_("try \"aktool s --oids\" for list of all available identifiers\n"));
                     return EXIT_FAILURE;
                   }
                   if( ki.oid_of_target->mode != algorithm ) {
                     aktool_error(_("%s is not valid identifier for algorithm"), optarg );
                     printf(
                     _("try \"aktool s --oid algorithm\" for list of all available algorithms\n"));
                     return EXIT_FAILURE;
                   }
                   break;

      /* устанавливаем имя генератора ключевой информации */
        case 205:   if(( ki.oid_of_generator = ak_oid_find_by_ni( optarg )) == NULL ) {
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
        case 206:   ki.name_of_file_for_generator = optarg;
                    break;

      /* устанавливаем размер конечного поля (в битах) */
        case 180: /* --field */
                   ki.field = atoi( optarg );
                   if(( ki.field != ak_galois256_size ) && ( ki.field != ak_galois512_size )) {
                     if( ki.field == 256 ) ki.field >>= 3;
                       else
                        if( ki.field == 512 ) ki.field >>= 3;
                          else {
                            aktool_error(_("incorrect value of field size,"
                                                " use \"--field 256\" or \"--field 512\" option"));
                            return EXIT_FAILURE;
                          }
                   }
                   break;

      /* устанавливаем размер матрицы (мастер-ключа) для схемы Блома */
        case 181: /* --size */
                   if(( ki.size = atoi( optarg )) == 0 ) ki.size = 512;
                   if( ki.size > 4096 ) ki.size = 4096; /* ограничение по реализации */
                   break;

      /* устанавливаем идентификатор/расширенное имя пользователя или владельца */
        case 182: /* --id */
                   memset( ki.user, 0, sizeof( ki.user ));
                   strncpy( ki.user, optarg, sizeof( ki.user ) -1 );
                   ki.lenuser = strlen( ki.user );
                   break;

        case 183: /* --hexid */
                   ki.lenuser = 0;
                   memset( ki.user, 0, sizeof( ki.user ));
                   if( ak_hexstr_to_ptr( optarg, ki.user,
                                              sizeof( ki.user ), ak_false ) == ak_error_ok ) {
                      ki.lenuser = ak_min(( strlen( optarg )%2 ) + ( strlen( optarg ) >> 1 ),
                                                                                sizeof( ki.user ));
                   }
                   if( ki.lenuser == 0 ) {
                       aktool_error(_("user identifier cannot be of zero length, "
                                                       "maybe input error, see --hexid %s%s%s"),
                                  ak_error_get_start_string(), optarg, ak_error_get_end_string( ));
                       return EXIT_FAILURE;
                     }
                   break;

     /* передача пароля через командную строку */
        case 248: /* --password */
                   memset( ki.password, 0, sizeof( ki.password ));
                   strncpy( ki.password, optarg, sizeof( ki.password ) -1 );
                   if(( ki.lenpass = strlen( ki.password )) == 0 ) {
                     aktool_error(_("password cannot be of zero length"));
                     return EXIT_FAILURE;
                   }
                   break;

        case 252: /* --key-password */
                   memset( ki.key_password, 0, sizeof( ki.key_password ));
                   strncpy( ki.key_password, optarg, sizeof( ki.key_password ) -1 );
                   if(( ki.lenkeypass = strlen( ki.key_password )) == 0 ) {
                     aktool_error(_("password cannot be of zero length"));
                     return EXIT_FAILURE;
                   }
                   break;

        case 249: /* --hexpass */
                   ki.lenpass = 0;
                   memset( ki.password, 0, sizeof( ki.password ));
                   if( ak_hexstr_to_ptr( optarg, ki.password,
                                              sizeof( ki.password ), ak_false ) == ak_error_ok ) {
                     ki.lenpass = ak_min(( strlen( optarg )%2 ) + ( strlen( optarg ) >> 1 ),
                                                                            sizeof( ki.password ));
                   }
                   if( ki.lenpass == 0 ) {
                       aktool_error(_("password cannot be of zero length, "
                                                       "maybe input error, see --hexpass %s%s%s"),
                                  ak_error_get_start_string(), optarg, ak_error_get_end_string( ));
                       return EXIT_FAILURE;
                     }
                   break;

        case 251: /* --key-hexpass */
                   ki.lenkeypass = 0;
                   memset( ki.key_password, 0, sizeof( ki.key_password ));
                   if( ak_hexstr_to_ptr( optarg, ki.key_password,
                                           sizeof( ki.key_password ), ak_false ) == ak_error_ok ) {
                     ki.lenkeypass = ak_min(( strlen( optarg )%2 ) + ( strlen( optarg ) >> 1 ),
                                                                         sizeof( ki.key_password ));
                   }
                   if( ki.lenkeypass == 0 ) {
                       aktool_error(_("password cannot be of zero length, "
                                                       "maybe input error, see --hexpass %s%s%s"),
                                  ak_error_get_start_string(), optarg, ak_error_get_end_string( ));
                       return EXIT_FAILURE;
                     }
                   break;

     /* устанавливаем имена файлов (в полном, развернутом виде) */
        case 'o': /* --o, --output-secret-key */
                  #ifdef _WIN32
                    GetFullPathName( optarg, FILENAME_MAX, ki.os_file, NULL );
                  #else
                    realpath( optarg , ki.os_file );
                  #endif
                    break;

        case 202: /* --op, --output-public-key */
                  #ifdef _WIN32
                    GetFullPathName( optarg, FILENAME_MAX, ki.op_file, NULL );
                  #else
                    realpath( optarg , ki.op_file );
                  #endif
                    break;

        case 203: /* --key */
                  #ifdef _WIN32
                    GetFullPathName( optarg, FILENAME_MAX, ki.key_file, NULL );
                  #else
                    realpath( optarg , ki.key_file );
                  #endif
                    break;

        case 208: /* --pubkey */
                  #ifdef _WIN32
                    GetFullPathName( optarg, FILENAME_MAX, ki.pubkey_file, NULL );
                  #else
                    realpath( optarg , ki.pubkey_file );
                  #endif
                    break;

        default:  /* обрабатываем ошибочные параметры */
                   if( next_option != -1 ) work = do_nothing;
                   break;
       }
   } while( next_option != -1 );
   if( work == do_nothing ) return aktool_key_help();

 /* начинаем работу с криптографическими примитивами */
   if( !aktool_create_libakrypt( )) return EXIT_FAILURE;
   ak_libakrypt_set_password_read_function( aktool_key_load_user_password );

 /* теперь вызов соответствующей функции */
   switch( work ) {
     case do_new:
       exit_status = aktool_key_new();
       break;

     default:
       exit_status = EXIT_FAILURE;
   }

 /* завершаем работу и выходим */
   aktool_destroy_libakrypt();

 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_new( void )
{
 /* сперва проверяем случаи, в которых генерация ключа отлична от обычной процедуры
    и требует дополнительных алгоритмических мер */
   if( ki.method != NULL ) {
     switch( ki.method->engine ) {
      case blom_master: return aktool_key_new_blom_master();
      case blom_subscriber: return aktool_key_new_blom_subscriber();
      case blom_pairwise: return aktool_key_new_blom_pairwise();

      default: aktool_error(_("the string %s (%s) is an identifier of %s which "
                                                    "does not used as key generation algorithm"),
          ki.method->name[0], ki.method->id[0], ak_libakrypt_get_engine_name( ki.method->engine ));
     }
     return EXIT_FAILURE;
   }

 /* теперь реализуем обычную процедуру, состоящую из генерации случайного вектора с помощью
    заданного генератора */

 return EXIT_SUCCESS;
}


/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_new_blom_master( void )
{
  struct blomkey master;
  int exitcode = EXIT_FAILURE;
  ak_pointer generator = NULL;

 /* формируем генератор случайных чисел */
  if( ki.name_of_file_for_generator != NULL ) {
    if( ak_random_create_file( generator = malloc( sizeof( struct random )),
                                                ki.name_of_file_for_generator ) != ak_error_ok ) {
      if( generator ) free( generator );
      return exitcode;
    }
    if( ki.verbose ) printf(_("generator: %s\n"), ki.name_of_file_for_generator );
  }
   else {
    if(( generator = ak_oid_new_object( ki.oid_of_generator )) == NULL ) return exitcode;
    if( ki.verbose ) printf(_("generator: %s\n"), ki.oid_of_generator->name[0] );
   }

  if( ki.verbose ) {
    printf(_("    field: GF(2^%u)\n"), ki.field << 3 );
    printf(_("     size: %ux%u\n  process: "), ki.size, ki.size );
    fflush( stdout );
  }

 /* вырабатываем ключ заданного размера */
  if( ak_blomkey_create_matrix( &master, ki.size, ki.field, generator ) != ak_error_ok ) {
    aktool_error(_("incorrect master key generation"));
    goto labex;
  }
  if( ki.verbose ) { printf(_("Ok\n\n")); }

 /* запрашиваем пароль для сохраняемых данных */
  if( !ki.lenpass  ) {
    if(( ki.lenpass = aktool_key_load_user_password_twice( ki.password, sizeof( ki.password ))) < 1 )
      goto labex1;
  }
 /* сохраняем созданный ключ в файле */
  if( ak_blomkey_export_to_file_with_password(
          &master,
          ki.password,
          ki.lenpass,
          ki.os_file,      /* если имя не задано,
                     то получаем новое имя файла */
          ( strlen( ki.os_file ) > 0 ) ? 0 : sizeof( ki.os_file )
    ) != ak_error_ok )
      aktool_error(_("wrong export a secret key to file %s%s%s"),
                              ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
     else {
       printf(_("secret key stored in %s%s%s file\n"),
                              ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
       exitcode = EXIT_SUCCESS;
     }

 labex1:
  ak_blomkey_destroy( &master );

 labex:
  if( ki.name_of_file_for_generator != NULL ) {
    ak_random_destroy( generator );
    free( generator );
  }
   else ak_oid_delete_object( ki.oid_of_generator, generator );

 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_new_blom_subscriber( void )
{
  int exitcode = EXIT_FAILURE;
  struct blomkey master, abonent;

 /* проверяем наличие имени пользователя */
  if( ki.lenuser == 0 ) {
    aktool_error(_("user or subscriber's name is undefined, use \"--id\" option" ));
    return exitcode;
  }
  if( strlen( ki.key_file ) == 0 ) {
    aktool_error(_("the file with master key is undefined, use \"--key\" option" ));
    return exitcode;
  }
 /* запрашиваем пароль для доступа к мастер ключу (однократно, без дублирования) */
  if( ki.verbose ) printf(_("using master key: %s\n"), ki.key_file );
  if( ki.lenkeypass == 0 ) {
    if(( ki.lenkeypass = aktool_key_load_user_password( ki.key_password,
                                                               sizeof( ki.key_password ))) < 1 ) {
       aktool_error(_("incorrect password reading"));
       return exitcode;
    }
  }

 /* считываем ключ из заданного файла
    если пароль определен в командой строке, то используем именно его */
  if( ak_blomkey_import_from_file_with_password( &master,
                                  ki.key_password, ki.lenkeypass, ki.key_file ) != ak_error_ok ) {
    aktool_error(_("incorrect loading a master key from %s file\n"), ki.key_file );
    return exitcode;
  }
 /* создаем ключ абонента */
  if( ki.verbose ) {
    if( strlen( ki.user ) == (size_t) ki.lenuser )
      printf(_("generation a %s key for %s: "), ki.method->name[0], ki.user );
     else printf(_("generation a %s key for %s: "), ki.method->name[0],
                                                ak_ptr_to_hexstr( ki.user, ki.lenuser, ak_false ));
    fflush( stdout );
  }
  if( ak_blomkey_create_abonent_key( &abonent, &master, ki.user, ki.lenuser ) != ak_error_ok ) {
    aktool_error(_("incorrect creation of the abonent's key"));
    goto labex1;
  }
  if( ki.verbose ) { printf(_("Ok\n\n")); }

 /* запрашиваем пароль для сохранения ключа абонента */
  if( !ki.lenpass  ) {
    if(( ki.lenpass = aktool_key_load_user_password_twice( ki.password, sizeof( ki.password ))) < 1 )
      goto labex2;
  }

 /* сохраняем созданный ключ в файле */
  if( ak_blomkey_export_to_file_with_password(
          &abonent,
          ki.password,
          ki.lenpass,
          ki.os_file,      /* если имя не задано,
                     то получаем новое имя файла */
          ( strlen( ki.os_file ) > 0 ) ? 0 : sizeof( ki.os_file )
    ) != ak_error_ok )
      aktool_error(_("wrong export a secret key to file %s%s%s"),
                              ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
     else {
       printf(_("secret key stored in %s%s%s file\n"),
                              ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
       exitcode = EXIT_SUCCESS;
     }

 labex2:
   ak_blomkey_destroy( &abonent );
 labex1:
   ak_blomkey_destroy( &master );

 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
/* создаем имя для ключа парной связи */
 static void aktool_key_new_blom_pairwise_keyname( void )
{
  time_t atime;
  struct hash ctx;
  ak_uint8 buffer[64];

 /* вырабатываем случайное имя файла */
   memset( buffer, 0, sizeof( buffer ));
   memcpy( buffer, ki.user, ak_min( (size_t) ki.lenuser, sizeof( buffer )));
   atime = time( NULL );
   memcpy( buffer + ( sizeof( buffer ) - sizeof( time_t )), &atime, sizeof( time_t ));
   ak_hash_create_streebog512( &ctx );
   ak_hash_ptr( &ctx, buffer, sizeof( buffer ), buffer, sizeof( buffer ));
   ak_hash_destroy( &ctx );
   ak_snprintf( ki.os_file, sizeof( ki.os_file ),
                                       "%s-pairwise.key", ak_ptr_to_hexstr( buffer, 8, ak_false ));
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_new_blom_pairwise( void )
{
  struct blomkey abonent;
  int exitcode = EXIT_FAILURE;

 /* проверяем наличие имени пользователя */
  if( ki.lenuser == 0 ) {
    aktool_error(_("user or subscriber's name is undefined, use \"--id\" option" ));
    return exitcode;
  }
 /* проверяем наличие файла с ключом пользователя */
  if( strlen( ki.key_file ) == 0 ) {
    aktool_error(_("the file with subscriber's key is undefined, use \"--key\" option" ));
    return exitcode;
  }
 /* проверяем, что алгоритм для нового ключа парной связи определен */
  if( ki.target_undefined == ak_false ) {
    if( ki.oid_of_target == NULL ) {
      aktool_error(_("the target cryptographic algorithm for pairwise key is undefined,"
                                                                     " use \"--target\" option" ));
      return exitcode;
    }
    switch( ki.oid_of_target->engine ) {
      case block_cipher:
      case hmac_function:
      case sign_function:
        break;

      default:
        aktool_error(_("an engine of the given target cryptographic"
                                                             " algorithm is not supported (%s)" ),
                                         ak_libakrypt_get_engine_name( ki.oid_of_target->engine ));
        return exitcode;
    }
  }

 /* запрашиваем пароль для доступа к ключу абонента (однократно, без дублирования) */
  if( ki.verbose ) printf(_("subscriber's key: %s\n"), ki.key_file );
  if( ki.lenkeypass == 0 ) {
    if(( ki.lenkeypass = aktool_key_load_user_password( ki.key_password,
                                                               sizeof( ki.key_password ))) < 1 ) {
       aktool_error(_("incorrect password reading"));
       return exitcode;
    }
  }
 /* считываем ключ из заданного файла
    если пароль определен в командой строке, то используем именно его */
  if( ak_blomkey_import_from_file_with_password( &abonent,
                                  ki.key_password, ki.lenkeypass, ki.key_file ) != ak_error_ok ) {
    aktool_error(_("incorrect loading an abonent key from %s file\n"), ki.key_file );
    return exitcode;
  }
 /* создаем ключ парной связи */
  if( ki.verbose ) {
    if( strlen( ki.user ) == (size_t) ki.lenuser )
      printf(_("generation a pairwise key for %s: "), ki.user );
     else printf(_("generation a pairwise key for %s: "),
                                                ak_ptr_to_hexstr( ki.user, ki.lenuser, ak_false ));
    fflush( stdout );
  }
  if( ki.target_undefined == ak_true ) { /* вырабатываем незашированный вектор */
    struct file fs;
    ak_uint8 key[64];

    if( ak_blomkey_create_pairwise_key_as_ptr( &abonent,
                                      ki.user, ki.lenuser, key, abonent.count ) != ak_error_ok ) {
      aktool_error(_("wrong pairwise key generation"));
      goto labex1;
    }
    if( ki.verbose ) { printf(_("Ok\n\n")); }
    if( strlen( ki.os_file ) == 0 ) aktool_key_new_blom_pairwise_keyname();
    if( ak_file_create_to_write( &fs, ki.os_file ) != ak_error_ok ) {
      aktool_error(_("incorrect key file creation"));
      goto labex1;
    }
    if( ak_file_write( &fs, key, abonent.count ) != abonent.count ) {
      aktool_error(_("incorrect write to %s%s%s file"),
                              ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
    }
     else {
       printf(_("secret key stored in %s%s%s file\n"),
                              ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
       exitcode = EXIT_SUCCESS;
     }
    ak_file_close( &fs );
  } /* конец генерации undefined key */

   else { /* вырабатываем секретный ключ для заданного опцией --target алгоритма */
     ak_pointer key = NULL;
     if(( key = ak_blomkey_new_pairwise_key( &abonent, ki.user, ki.lenuser,
                                                                   ki.oid_of_target )) == NULL ) {
      aktool_error(_("wrong pairwise key generation"));
      goto labex1;
     }
     if( ki.verbose ) { printf(_("Ok\n\n")); }

    /* вот еще что надо бы не забыть */
     if( strlen( ki.keylabel ) != 0 ) {
       if( ki.verbose ) printf(_("key label: %s\n"), ki.keylabel );
       ak_skey_set_label( (ak_skey)key, ki.keylabel, 0 );
     }

    /* запрашиваем пароль для сохранения ключа абонента */
     if( ki.lenpass == 0 ) {
       if(( ki.lenpass =
                   aktool_key_load_user_password_twice( ki.password, sizeof( ki.password ))) < 1 )
         goto labex2;
     }

   /* теперь экпортируем ключ */
     if( ak_skey_export_to_file_with_password(
          key,
          ki.password,
          ki.lenpass,
          ki.os_file,      /* если имя не задано,
                     то получаем новое имя файла */
         ( strlen( ki.os_file ) > 0 ) ? 0 : sizeof( ki.os_file ),
          ki.format
       ) != ak_error_ok ) aktool_error(_("wrong export a secret key to file %s%s%s"),
                              ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
     else {
       printf(_("secret key stored in %s%s%s file\n"),
                              ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
       exitcode = EXIT_SUCCESS;
     }
     labex2: ak_oid_delete_object( ki.oid_of_target, key );
  }

 labex1:
   ak_blomkey_destroy( &abonent );

 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- *
 \param create_secret флаг должен установлен для создания секретного ключа
 \param create_pair флаг должен быть установлен для генерации пары асимметричных ключей
 * ----------------------------------------------------------------------------------------------- */
 int aktool_key_new_keypair( bool_t create_secret , bool_t create_pair )
{

 return EXIT_FAILURE;
}

/* ----------------------------------------------------------------------------------------------- */

// СДЕЛАТЬ -c <request> с параметром, а опцию --req удалить
//     " -c, --cert              create a public key certificate from a given request\n"
// Сделать -subj = "/cn/su/sn/ct/ln/st/or/ou/em" --id

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_help( void )
{
  printf(
   _("aktool key [options]  - key generation and management functions\n\n"
     "available options:\n"
     " -a, --algorithm         specify the method or the cryptographic algorithm for key generation\n"
     "                         this option needs to be used in some key generation schemes, e.g. in Blom scheme\n"
     "     --curve             set the elliptic curve name or identifier for asymmetric keys\n"
     "     --days              set the days count to expiration date of secret or public key\n"
     "     --field             bit length which used to define the galois field [ enabled values: 256, 512 ]\n"
     "     --format            set the format of output file [ enabled values: der, pem, certificate ]\n"
     "     --hexid             user or abonent's identifier as hexademal string\n"
     "     --hexpass           specify the password directly in command line as hexademal string\n"
     "     --id                set a generalized name or identifier for the user, subscriber or key owner\n"
     "                         if the identifier contains control commands, it is interpreted as a set of names\n"
     "     --key               specify the name of file with the secret key\n"
     "                         this can be a master key or issuer's key which is used to sign a certificate\n"
     "     --key-hexpass       set the password for the secret key to be read directly in command line as hexademal string\n"
     "     --key-password      set the password for the secret key to be read directly in command line\n"
     "     --label             assign the user-defined label to secret key\n"
     " -n, --new               generate a new key or key pair for specified target\n"
     "     --op                short form of --output-public-key option\n"
     "     --output-public-key set the file name for the new public key request\n"
     " -o, --output-secret-key set the file name for the new secret key\n"
     "     --password          specify the password for storing a secret key directly in command line\n"
     "     --pubkey            name of the issuer's public key, information from which will be placed in the certificate\n"
     "     --random            set the name or identifier of random sequences generator\n"
     "                         the generator will be used to create a new key [ default value: \"%s\" ]\n"
     "     --random-file       set the name of file with random sequence\n"
     "     --size              set the dimension of secret master key in blom scheme [ maximal value: 4096 ]\n"
     " -t, --target            specify the name of the cryptographic algorithm for the new generated key\n"
     "                         one can use any supported names or identifiers of algorithm,\n"
     "                         or \"undefined\" value for generation the plain unecrypted key unrelated to any algorithm\n"
     "     --to                another form of --format option\n"
     "     --verbose           show the additional information\n\n"
     "options used for customizing a public key's certificate:\n"
     "     --authority-keyid   add an authority key identifier to certificate being created\n"
     "                         this option should only be used for self-signed certificates,\n"
     "                         in other cases it is used by default\n"
     "     --authority-name    add an issuer's generalized name to the authority key identifier extension\n"
     "     --ca                use as certificate authority [ enabled values: true, false ]\n"
     "     --pathlen           set the maximal length of certificate's chain\n"
     "     --digital-signature use for verifying a digital signatures of user data\n"
     "     --content-commitment\n"
     "     --key-encipherment  use for encipherment of secret keys\n"
     "     --data-encipherment use for encipherment of user data (is not usally used)\n"
     "     --key-agreement     use in key agreement protocols for subject's authentication\n"
     "     --key-cert-sign     use for verifying of public key's certificates\n"
     "     --crl-sign          use for verifying of revocation lists of certificates\n"
  ),
  aktool_default_generator
 );
  aktool_print_common_options();

  printf(_("for usage examples try \"man aktool\"\n" ));

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                   aktool_key.c  */
/* ----------------------------------------------------------------------------------------------- */
