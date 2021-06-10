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
 int aktool_key_new_keypair( bool_t );
 int aktool_key_verify_key( int argc , char *argv[] );
 int aktool_key_input_name( ak_verifykey );

/* ----------------------------------------------------------------------------------------------- */
 #define aktool_magic_number (113)

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key( int argc, char *argv[] )
{
  int next_option = 0, exit_status = EXIT_FAILURE;
  enum { do_nothing, do_new, do_show, do_verify, do_cert } work = do_nothing;

 /* параметры, которые устанавливаются по умолчанию */
  ki.oid_of_generator = ak_oid_find_by_name( aktool_default_generator );

 /* параметры, запрашиваемые пользователем */
  const struct option long_options[] = {
   /* сначала уникальные */
     { "algorithm",           1, NULL,  'a' },
     { "new",                 0, NULL,  'n' },
     { "show",                1, NULL,  's' },
     { "verify",              0, NULL,  'v' },
     { "cert",                1, NULL,  'c' },
     { "output-secret-key",   1, NULL,  'o' },
     { "to",                  1, NULL,  250 },
     { "format",              1, NULL,  250 },
     { "outpass-hex",         1, NULL,  249 },
     { "outpass",             1, NULL,  248 },
     { "inpass-hex",          1, NULL,  251 },
     { "inpass",              1, NULL,  252 },
     { "curve",               1, NULL,  247 },
     { "days",                1, NULL,  246 },
     { "target",              1, NULL,  't' },
     { "ca-cert",             1, NULL,  208 },
     { "label",               1, NULL,  207 },
     { "random-file",         1, NULL,  206 },
     { "random",              1, NULL,  205 },

     { "key",                 1, NULL,  203 },
     { "ca-key",              1, NULL,  203 },
     { "op",                  1, NULL,  202 },
     { "output-public-key",   1, NULL,  202 },

   /* флаги для генерации ключей схемы Блома */
     { "field",               1, NULL,  180 },
     { "size",                1, NULL,  181 },
     { "id",                  1, NULL,  182 },
     { "id-hex",              1, NULL,  183 },

    /* флаги использования открытого ключа */
     { "digital-signature",   0, NULL,  190 },
     { "content-commitment",  0, NULL,  191 },
     { "key-encipherment",    0, NULL,  192 },
     { "data-encipherment",   0, NULL,  193 },
     { "key-agreement",       0, NULL,  194 },
     { "key-cert-sign",       0, NULL,  195 },
     { "crl-sign",            0, NULL,  196 },
     { "ca-ext",              1, NULL,  197 },
     { "pathlen",             1, NULL,  198 },
     { "authority-name",      0, NULL,  200 },

     aktool_common_functions_definition,
     { NULL,                  0, NULL,   0  },
  };

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, aktool_common_letters_definition"ns:a:o:t:vc:", long_options, NULL ); // hns:a:o:t:vc:
       switch( next_option )
      {
        aktool_common_functions_run( aktool_key_help );

      /* управляющие команды */
        case 'n' : /* --new */
                   work = do_new;
                   break;
        case 'v' : /* --verify */
                   work = do_verify;
                   break;

        case 't' : /* --target */
                   if( strncmp( optarg, "undefined", 9 ) == 0 ) {
                     ki.oid_of_target = NULL;
                     ki.target_undefined = ak_true;
                     break;
                   }
                   ki.target_undefined = ak_false;
                   if(( ki.oid_of_target = ak_oid_find_by_ni( optarg )) == NULL ) {
                      aktool_error(_("using unsupported name or identifier (%s) "), optarg );
                      printf(_("try \"aktool s --oids\" for list of all available identifiers\n"));
                     return EXIT_FAILURE;
                   }
                   if( ki.oid_of_target->mode != algorithm ) {
                     aktool_error(_("%s (%s) is not valid identifier for algorithm"),
                                     optarg, ak_libakrypt_get_mode_name( ki.oid_of_target->mode ));
                     printf(
                     _("try \"aktool s --oid algorithm\" for list of all available algorithms\n"));
                     return EXIT_FAILURE;
                   }
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
                   memset( ki.userid, 0, sizeof( ki.userid ));
                   strncpy( ki.userid, optarg, sizeof( ki.userid ) -1 );
                   ki.lenuser = strlen( ki.userid );
                   break;

        case 183: /* --id-hex */
                   ki.lenuser = 0;
                   memset( ki.userid, 0, sizeof( ki.userid ));
                   if( ak_hexstr_to_ptr( optarg, ki.userid,
                                              sizeof( ki.userid ), ak_false ) == ak_error_ok ) {
                      ki.lenuser = ak_min(( strlen( optarg )%2 ) + ( strlen( optarg ) >> 1 ),
                                                                              sizeof( ki.userid ));
                   }
                   if( ki.lenuser == 0 ) {
                     aktool_error(_("user identifier cannot be of zero length, "
                                                "maybe input error, check option --hexid %s%s%s"),
                                  ak_error_get_start_string(), optarg, ak_error_get_end_string( ));
                       return EXIT_FAILURE;
                     }
                   break;

      /* передача паролей через командную строку */
        case 248: /* --outpass */
                   memset( ki.outpass, 0, sizeof( ki.outpass ));
                   strncpy( ki.outpass, optarg, sizeof( ki.outpass ) -1 );
                   if(( ki.lenoutpass = strlen( ki.outpass )) == 0 ) {
                     aktool_error(_("the password cannot be zero length"));
                     return EXIT_FAILURE;
                   }
                   break;

        case 252: /* --inpass */
                   memset( ki.inpass, 0, sizeof( ki.inpass ));
                   strncpy( ki.inpass, optarg, sizeof( ki.inpass ) -1 );
                   if(( ki.leninpass = strlen( ki.inpass )) == 0 ) {
                     aktool_error(_("the password cannot be zero length"));
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
      /* запоминаем пользовательское описание ключа */
        case 207:   /* --label */
                    ki.keylabel = optarg;
                    break;

      /* интервал действия ключа */
        case 246: /* --days */
                    ki.days = atoi( optarg );
                    if( !ki.days ) ki.days = 365;
                    break;

      /* проверяем идентификатор кривой */
        case 247: /* --curve  */
                   if(( ki.curve = ak_oid_find_by_ni( optarg )) == NULL ) {
                     aktool_error(
                        _("using unsupported name or identifier \"%s\" for elliptic curve"),
                                                                                          optarg );
                     printf(
                        _("try \"aktool s --oid curve\" for list of all available identifiers\n"));
                     return EXIT_FAILURE;
                   }
                   if(( ki.curve->engine != identifier ) || ( ki.curve->mode != wcurve_params )) {
                      aktool_error(_("%s is not valid identifier for elliptic curve"), optarg );
                      printf(
                        _("try \"aktool s --oid curve\" for list of all available identifiers\n"));
                       return EXIT_FAILURE;
                     }
                   break;

      /* устанавливаем имена файлов (в полном, развернутом виде) */
        case 'o': /* -o, --output-secret-key */
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

        case 203: /* --key, --ca-key */
                  #ifdef _WIN32
                    GetFullPathName( optarg, FILENAME_MAX, ki.key_file, NULL );
                  #else
                    realpath( optarg , ki.key_file );
                  #endif
                    break;

        case 208: /* --ca-cert */
                  #ifdef _WIN32
                    GetFullPathName( optarg, FILENAME_MAX, ki.capubkey_file, NULL );
                  #else
                    realpath( optarg , ki.capubkey_file );
                  #endif
                    break;

      /* определяем формат выходных данных */
        case 250: /* --to, --format  */
                  {
                    char tmp[4];
                    ak_uint32 i = 0;
                    memset( tmp, 0, sizeof( tmp ));
                    strncpy( tmp, optarg, 3 );
                    for( i = 0; i < sizeof( tmp )-1; i ++ ) tmp[i] = toupper( tmp[i] );

                    ki.format = asn1_der_format;
                    if( strncmp( tmp, "DER", 3 ) == 0 )
                      ki.format = asn1_der_format;
                     else
                       if( strncmp( tmp, "PEM", 3 ) == 0 )
                         ki.format = asn1_pem_format;
                        else
                          if( strncmp( tmp, "CER", 3 ) == 0 )
                            ki.format = aktool_magic_number;
                           else {
                             aktool_error(_("%s is not valid format of output data"), optarg );
                             return EXIT_FAILURE;
                           }
                  }
                   break;

        default:  /* обрабатываем ошибочные параметры */
                   if( next_option != -1 ) work = do_nothing;
                   break;
      }
  } while( next_option != -1 );
  if( work == do_nothing ) return aktool_key_help();

 /* начинаем работу с криптографическими примитивами */
  if( !aktool_create_libakrypt( )) return EXIT_FAILURE;

 /* теперь вызов соответствующей функции */
  switch( work ) {
    case do_new:
      if(( ki.generator = aktool_key_new_generator()) == NULL ) {
        aktool_error(_("incorrect creation of random sequences generator"));
        exit_status = EXIT_FAILURE;
      }
       else {
              ak_random gptr = ki.generator;
              exit_status = aktool_key_new();
              ak_ptr_wipe( &ki, sizeof( aktool_ki_t ), gptr );
              aktool_key_delete_generator( gptr );
            }
      break;

    case do_show:
      break;

    case do_verify: exit_status = aktool_key_verify_key( argc, argv );
      break;

    case do_cert:
      break;

    default:
      exit_status = EXIT_FAILURE;
  }

 /* завершаем работу и выходим */
   aktool_destroy_libakrypt();
 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
/*                             Генерация новой ключевой информации                                 */
/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_new( void )
{
 /* сперва проверяем случаи, в которых генерация ключа отлична от обычной процедуры
    и требует дополнительных алгоритмических мер */


 /* теперь реализуем обычную процедуру, состоящую из генерации случайного вектора с помощью
    заданного генератора */
  /* нужно обязательно определиться с типом алгоритма (контейнера) для создаваемого ключа */
   if( ki.oid_of_target == NULL ) {
     aktool_error(_("use --target option and set the name or identifier "
                                                      "of cryptographic algorithm for a new key"));
     return EXIT_FAILURE;
   }

  /* запускаем процедуру генерации ключа или ключевой пары */
   switch( ki.oid_of_target->engine ) {
    case block_cipher:
    case hmac_function:
      return aktool_key_new_keypair( ak_false );

    case sign_function: /* создаем пару ключей */
      return aktool_key_new_keypair( ak_true );

    default: aktool_error(_("the string %s (%s) is an identifier of %s which "
                                                             "does not use a cryptographic key"),
                                              ki.oid_of_target->name[0], ki.oid_of_target->id[0],
                                        ak_libakrypt_get_engine_name( ki.oid_of_target->engine ));
      return EXIT_FAILURE;
   }

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                    реализация базовой схемы                                     */
/* ----------------------------------------------------------------------------------------------- *
 \param create_secret флаг должен установлен для создания секретного ключа
 \param create_pair флаг должен быть установлен для генерации пары асимметричных ключей
 * ----------------------------------------------------------------------------------------------- */
 int aktool_key_new_keypair( bool_t create_pair )
{
  ak_pointer key = NULL;
  time_t now = time( NULL );
  int exitcode = EXIT_FAILURE;

 /* создаем ключ */
  if(( key = ak_oid_new_object( ki.oid_of_target )) == NULL ) return exitcode;

 /* для асимметричных ключей устанавливаем кривую */
  if( ki.oid_of_target->engine == sign_function ) {
    if( ki.curve == NULL ) ki.curve = ak_oid_find_by_name( "cspa" );
    if( ak_signkey_set_curve( key, ki.curve->data ) != ak_error_ok ) {
      aktool_error(_("using non applicable elliptic curve (%s)"), ki.curve->name[0] );
      goto labex2;
    }
  }

 /* вырабатываем случайный секретный ключ */
  if( ki.oid_of_target->func.first.set_key_random( key, ki.generator ) != ak_error_ok ) {
    aktool_error(_("incorrect creation of a random secret key value"));
    goto labex2;
  }

 /* устанавливаем срок действия, в сутках, начиная с текущего момента */
  if( ak_skey_set_validity( key, now, now + ki.days*86400 ) != ak_error_ok ) {
    aktool_error(_("incorrect assigning the validity of secret key"));
    goto labex2;
  }

 /* устанавливаем метку */
  if( ki.keylabel != NULL ) {
    if( ak_skey_set_label( key, ki.keylabel, strlen( ki.keylabel )) != ak_error_ok ) {
      aktool_error(_("incorrect assigning the label of secret key"));
      goto labex2;
    }
  }

 /* !!! переходим к открытому ключу !!! */
 /* далее, мы создаем запрос на сертификат открытого ключа или
    самоподписаный сертификат открытого ключа */
  if( create_pair ) {
    struct verifykey vkey;

   /* вырабатываем открытый ключ,
      это позволяет выработать номер открытого ключа, а также присвоить ему имя и ресурс */
    if( ak_verifykey_create_from_signkey( &vkey, key ) != ak_error_ok ) {
      aktool_error(_("incorrect creation of public key"));
      goto labex2;
    }
   /* создаем обобщенное имя владельца ключей */
    if( aktool_key_input_name( &vkey ) != ak_error_ok ) {
      aktool_error(_("incorrect creation of owner's distinguished name"));
      goto labex2;
    }

    if( ki.format == aktool_magic_number ) { /* сохраняем открытый ключ как корневой сертификат */
      aktool_error( "мы не сохраняем самоподписаные сертификаты" );


    }
     else { /* сохраняем запрос на сертификат */
        if( ak_verifykey_export_to_request( &vkey, key, ki.generator, ki.op_file,
           ( strlen( ki.op_file ) > 0 ) ? 0 : sizeof( ki.op_file ), ki.format ) != ak_error_ok ) {
          aktool_error(_("wrong export a public key to request %s%s%s"),
                              ak_error_get_start_string(), ki.op_file, ak_error_get_end_string( ));
          goto labex2;
        } else {
            printf(_("public key stored in %s%s%s file as certificate's request\n\n"),
                              ak_error_get_start_string(), ki.op_file, ak_error_get_end_string( ));
          }
     }

    ak_verifykey_destroy( &vkey );
  } /* конец if( create_pair ) */

 /* мастерим пароль для сохранения секретного ключа */
  if( ki.lenoutpass == 0 ) {
    if(( ki.lenoutpass =
                    aktool_key_load_user_password_twice( ki.outpass, sizeof( ki.outpass ))) < 1 ) {
      exitcode = EXIT_FAILURE;
      goto labex2;
    }
  }

 /* сохраняем созданный ключ в файле */
  if( ak_skey_export_to_file_with_password(
          key,            /* ключ */
          ki.outpass,     /* пароль */
          ki.lenoutpass,  /* длина пароля */
          ki.os_file,     /* если имя не задано,
                     то получаем новое имя файла */
          ( strlen( ki.os_file ) > 0 ) ? 0 : sizeof( ki.os_file ),
          ki.format
     ) != ak_error_ok ) {
     aktool_error(_("wrong export a secret key to file %s%s%s"),
                              ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
     exitcode = EXIT_FAILURE;
     goto labex2;
  } else {
     /* секретный ключ хорошо хранить в хранилище, а не в файле */
     printf(_("secret key stored in %s%s%s file\n"),
                              ak_error_get_start_string(), ki.os_file, ak_error_get_end_string( ));
     exitcode = EXIT_SUCCESS;
    }

  labex2:
   ak_oid_delete_object( ki.oid_of_target, key );

 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
 static int aktool_key_input_name_from_console_line( ak_verifykey key,
                                                                 const char *sh, const char *lg  )
{
  size_t len = 0;
  char string[256];
  char *ptr = NULL;
  int error = ak_error_not_ready;

  if(( ptr = strstr( ki.userid, sh )) != NULL ) {
    ptr+=4; /* мы предполагаем, что на вход подается /xx= */
    len = 0;
    while( len < strlen( ptr )) {
      if( ptr[len]   == '/') break;
      ++len;
    }
    if( len > 0 ) {
      memset( string, 0, sizeof( string ));
      memcpy( string, ptr, ak_min( len, sizeof( string ) -1));
      error = ak_verifykey_add_name_string( key, lg, string );
    }
  }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/* в короткой форме мы поддерживаем флаги /cn/su/sn/ct/ln/st/or/ou/em (передается через --id)      */
/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_input_name_from_console( ak_verifykey key )
{
  int error = ak_error_ok, found = ak_false;

  if( aktool_key_input_name_from_console_line( key,
                                        "/em=", "email-address" ) == ak_error_ok ) found = ak_true;
  if( aktool_key_input_name_from_console_line( key,
                                          "/cn=", "common-name" ) == ak_error_ok ) found = ak_true;
  if( aktool_key_input_name_from_console_line( key,
                                              "/su=", "surname" ) == ak_error_ok ) found = ak_true;
  if( aktool_key_input_name_from_console_line( key,
                                        "/sn=", "serial-number" ) == ak_error_ok ) found = ak_true;
  if( aktool_key_input_name_from_console_line( key,
                                         "/ct=", "country-name" ) == ak_error_ok ) found = ak_true;
  if( aktool_key_input_name_from_console_line( key,
                                        "/lt=", "locality-name" ) == ak_error_ok ) found = ak_true;
  if( aktool_key_input_name_from_console_line( key,
                               "/st=", "state-or-province-name" ) == ak_error_ok ) found = ak_true;
  if( aktool_key_input_name_from_console_line( key,
                                       "/sa=", "street-address" ) == ak_error_ok ) found = ak_true;
  if( aktool_key_input_name_from_console_line( key,
                                         "/or=", "organization" ) == ak_error_ok ) found = ak_true;
  if( aktool_key_input_name_from_console_line( key,
                                    "/ou=", "organization-unit" ) == ak_error_ok ) found = ak_true;
  if( !found ) {
    error = ak_verifykey_add_name_string( key, "common-name", ki. userid );
  }

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_input_name( ak_verifykey key )
{
  size_t len = 0;
  char string[256];
  bool_t noname = ak_true;

 /* a. Проверяем, задана ли строка с расширенным именем владельца */
  if( ki.lenuser > 0 ) return aktool_key_input_name_from_console( key );

 /* b. Выводим стандартное пояснение */
  printf(_(" -----\n"
   " You are about to be asked to enter information that will be incorporated\n"
   " into your certificate request.\n"
   " What you are about to enter is what is called a Distinguished Name or a DN.\n"
   " There are quite a few fields but you can leave some blank.\n"
   " For some fields there will be a default value.\n"
   " If you do not want to provide information just enter a string of one or more spaces.\n"
   " -----\n"));

 /* Вводим расширенное имя с клавиатуры
    1. Country Name */

  ak_snprintf( string, len = sizeof( string ), "RU" );
  if( ak_string_read(_("Country Name (2 letter code)"), string, &len ) == ak_error_ok ) {
   #ifdef AK_HAVE_CTYPE_H
    string[0] = toupper( string[0] );
    string[1] = toupper( string[1] );
   #endif
    string[2] = 0;
    if( len && ( ak_verifykey_add_name_string( key,
                                      "country-name", string ) == ak_error_ok )) noname = ak_false;
  }
 /* 2. State or Province */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("State or Province"), string, &len ) == ak_error_ok )
    if( len && ( ak_verifykey_add_name_string( key,
                            "state-or-province-name", string ) == ak_error_ok )) noname = ak_false;
 /* 3. Locality */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Locality (eg, city)"), string, &len ) == ak_error_ok )
    if( len && ( ak_verifykey_add_name_string( key,
                                     "locality-name", string ) == ak_error_ok )) noname = ak_false;
 /* 4. Organization */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Organization (eg, company)"), string, &len ) == ak_error_ok )
    if( len && ( ak_verifykey_add_name_string( key,
                                      "organization", string ) == ak_error_ok )) noname = ak_false;
 /* 5. Organization Unit*/
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Organization Unit"), string, &len ) == ak_error_ok )
    if( len && ( ak_verifykey_add_name_string( key,
                                 "organization-unit", string ) == ak_error_ok )) noname = ak_false;
 /* 6. Street Address */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Street Address"), string, &len ) == ak_error_ok )
    if( len && ( ak_verifykey_add_name_string( key,
                                    "street-address", string ) == ak_error_ok )) noname = ak_false;
 /* 7. Common Name */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Common Name"), string, &len ) == ak_error_ok )
    if( len && ( ak_verifykey_add_name_string( key,
                                       "common-name", string ) == ak_error_ok )) noname = ak_false;
 /* 8. email address */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Email Address"), string, &len ) == ak_error_ok )
    if( len && ( ak_verifykey_add_name_string( key,
                                     "email-address", string ) == ak_error_ok )) noname = ak_false;
  if( noname ) {
    aktool_error(
   _("generation of a secret or public keys without any information about owner are not allowed"));
    return ak_error_invalid_value;
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                        проверка подписи под запросами и сертификатами                           */
/* ----------------------------------------------------------------------------------------------- */
 static int aktool_key_verify_print_request( ak_verifykey vkey, ak_request_opts reqopt )
{  
  ak_asn1 lst = NULL;
  size_t i = 0, ts = ak_hash_get_tag_size( &vkey->ctx );

  printf(_("Certificate's request\n"));
  printf(_("  subject: %s\n"), ak_tlv_get_string_from_global_name( vkey->name, "2.5.4.3", NULL ));

 /* начинаем перебор всех элементов */
  if(( lst = vkey->name->data.constructed ) != NULL ) {
    ak_asn1_first( lst );
    do{
        ak_oid oid = NULL;
        ak_pointer ptr = NULL;
        ak_asn1 sq = lst->current->data.constructed;

        ak_asn1_first( sq = sq->current->data.constructed );
        ak_tlv_get_oid( sq->current, &ptr );
        if(( oid = ak_oid_find_by_id( ptr )) != NULL ) {
          char buff[128];
          ak_uint32 sz = 0;
          ak_asn1_next( sq );
         /* мы копируем данные во временный буффер перед выводом, это спасает printf от чтения
                                                          последнего ненулевого байта в данных */
          sz = ak_min( sizeof( buff ) -1, sq->current->len );
          memcpy( buff, sq->current->data.primitive, sz );
          buff[sz] = 0;
          printf("    %s (%s): %s\n", oid->name[1], _( oid->name[0] ), buff );
        }
    } while( ak_asn1_next( lst ));
  }

 /* информация о ключе */
  printf(_("  public key (%s ... %u bytes)\n    x:  "),
                         ak_ptr_to_hexstr( vkey->number, ak_min( 10, vkey->numlen ), ak_false ),
                                                                    ( unsigned int )vkey->numlen );
  for( i = 0; i < ts; i++ ) {
    printf("%02X ", ((ak_uint8 *)vkey->qpoint.x)[i] );
    if(( i%16 == 15) && ( i != ts-1 )) printf("\n\t");
  }
  printf("\n    y:  ");
  for( i = 0; i < ts; i++ ) {
    printf("%02X ", ((ak_uint8 *)vkey->qpoint.y)[i] );
    if(( i%16 == 15) && ( i != ts-1 )) printf("\n\t");
  }
  printf(_("\n    elliptic curve:\n\t%s (%u bits)\n"),
                                ak_oid_find_by_data( vkey->wc )->name[0], ( vkey->wc->size << 6 ));
 /* информация о файле и его содержимом */
  printf(_("  request:\n    type: PKCS#10 (P 1323565.1.023-2018)\n    version: %d\n"),
                                                                                 reqopt->version );
  printf(_("  algorithm: %s\n"), vkey->oid->name[0] );
  printf(_("  signature:\n"));
  for( i = 0; i < 2*ts; i++ ) {
    if( i%16 == 0 ) printf("\t");
    printf("%02X ", reqopt->signature[i] );
    if(i%16 == 15) printf("\n");
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_verify_key( int argc , char *argv[] )
{
  struct verifykey vkey;
  struct request_opts reqopt;
  int errcount = 0, exitcode = EXIT_SUCCESS;

  ++optind; /* пропускаем набор управляющих команд (k -v или key --verify) */
  if( optind < argc ) {
    while( optind < argc ) {
        char *value = argv[optind++]; /* получаем указатель на запрашиваемое имя файла */
        if( ak_file_or_directory( value ) == DT_REG ) {
         /* только здесь начинается процесс обработки запроса или сертификата
            сначала формируем полное имя файла, потом опробуем содержимое */
          #ifdef _WIN32
            GetFullPathName( value, FILENAME_MAX, ki.pubkey_file, NULL );
          #else
            realpath( value , ki.pubkey_file );
          #endif
         /* опробуем содержимое файла как запрос на сертификат */
            switch( ak_verifykey_import_from_request( &vkey, ki.pubkey_file, &reqopt )) {
              case ak_error_ok:
                /* выводим ключ и переходим к следующему файлу */
                 if( ki.verbose ) aktool_key_verify_print_request( &vkey, &reqopt );
                 if( !ki.quiet ) printf(_("Verified: Ok\n"));
                 ak_verifykey_destroy( &vkey ); /* не забыть убрать за собой */
                 continue;
              case ak_error_not_equal_data:
                 if( !ki.quiet ) printf(_("Verified: No\n"));
                 errcount++;
                 continue;
              default:
                 break;
            }

           /* опробуем файл как сертификат открытого ключа

              ...

           */

            aktool_error(_("unsupported file %s"), value );
            errcount++;
        }
   }
  }
   else {
     aktool_error(_("certificate ot certificate's request is not "
                                                 "specified as the last argument of the program"));
     exitcode = EXIT_FAILURE;
    }

  if( errcount ) {
    aktool_error(_("aktool found %d error(s), "
                 "rerun aktool with \"--audit stderr\" option or see syslog messages"), errcount );
    exitcode = EXIT_FAILURE;
  }

 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                 вывод справочной информации                                     */
/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_help( void )
{
  printf(
   _("aktool key [options]  - key generation and management functions\n\n"
     "available options:\n"
     " -a, --algorithm         specify the method or the cryptographic algorithm for key generation\n"
     "                         this option needs to be used in some key generation schemes, e.g. in Blom scheme\n"
     "     --ca-cert           set the name of the certificate authorithy's public key\n"
     "     --ca-key            another form of --key option used to sign the certificate\n"
     " -c, --cert              sign the request and generate the certificate of public key\n"
     "     --curve             set the elliptic curve name or identifier for asymmetric keys\n"
     "     --days              set the days count to expiration date of secret or public key\n"
     "     --field             bit length which used to define the galois field [ enabled values: 256, 512 ]\n"
     "     --format            set the format of output file [ enabled values: der, pem, certificate ]\n"
     "     --id                set a generalized name or identifier for the user, subscriber or key owner\n"
     "                         if the identifier contains control commands, it is interpreted as a set of names\n"
     "     --id-hex            set a user or suscriber's identifier as hexademal string\n"
     "                         this option does not apply to public keys\n"
     "     --inpass            set the password for the secret key to be read directly in command line\n"
     "     --inpass-hex        set the password for the secret key to be read directly in command line as hexademal string\n"
     "     --key               specify the name of file with the secret key\n"
     "                         this can be a master key or certificate authority's secret key which is used to sign a certificate\n"
     "     --label             assign the user-defined label to secret key\n"
     " -n, --new               generate a new key or key pair for specified target\n"
     "     --op                short form of --output-public-key option\n"
     "     --outpass           set the password for the secret key to be stored directly on the command line\n"
     "     --outpass-hex       set the password for the secret key to be stored directly on the command line as hexademal string\n"
     "     --output-public-key set the file name for the new public key request\n"
     " -o, --output-secret-key set the file name for the new secret key\n"
     "     --random            set the name or identifier of random sequences generator\n"
     "                         the generator will be used to create a new key [ default value: \"%s\" ]\n"
     "     --random-file       set the name of file with random sequence\n"
     " -s, --show              output the parameters of the secret key or public key's request or certificate\n"
     "     --size              set the dimension of secret master key, in particular, for blom scheme [ maximal value: 4096 ]\n"
     " -t, --target            specify the name of the cryptographic algorithm for the new generated key\n"
     "                         one can use any supported names or identifiers of algorithm,\n"
     "                         or \"undefined\" value for generation the plain unecrypted key unrelated to any algorithm\n"
     "     --to                another form of --format option\n"
     " -v, --verify            verify the public key's request or certificate\n\n"
     "options used for customizing a public key's certificate:\n"
     "     --authority-name    add an issuer's generalized name to the authority key identifier extension\n"
     "     --ca-ext            use as certificate authority [ enabled values: true, false ]\n"
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
