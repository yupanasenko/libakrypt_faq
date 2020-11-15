 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <aktool.h>

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_help( void );
 int aktool_key_new( void );
 int aktool_key_certificate( void );
 int aktool_key_new_keypair( bool_t , bool_t );
 int aktool_key_input_name( ak_pointer );
 int aktool_key_print_disclaimer( void );

/* ----------------------------------------------------------------------------------------------- */
#if defined(__unix__) || defined(__APPLE__)
  #define aktool_default_denerator  "dev-random"
#else
  #ifdef AK_HAVE_WINDOWS_H
    #define aktool_default_denerator "winrtl"
  #else
    #define aktool_default_denerator "lcg"
  #endif
#endif

#define aktool_magic_number (113)

/* ----------------------------------------------------------------------------------------------- */
 static struct key_info {
   ak_oid algorithm;
   ak_oid oid_of_generator;
   char *name_of_file_for_generator;
   export_format_t format;
   ak_oid curve;
   size_t days;
   struct certificate_opts opts;
   char password[aktool_password_max_length];
   char keylabel[256];

   char os_file[FILENAME_MAX]; /* сохраняем секретный ключ */
   char op_file[FILENAME_MAX];  /* сохраняем открытый ключ */
   char req_file[FILENAME_MAX];    /* читаем открытый ключ */
   char key_file[FILENAME_MAX];   /* читаем секретный ключ */
 } ki;

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key( int argc, tchar *argv[] )
{
  char tmp[4];
  size_t i = 0;
  int next_option = 0, exit_status = EXIT_FAILURE;
  enum { do_nothing, do_new, do_cert } work = do_nothing;

 /* параметры, запрашиваемые пользователем */
  const struct option long_options[] = {
   /* сначала уникальные */
     { "algorithm",           1, NULL,  'a' },
     { "cert",                0, NULL,  'c' },
     { "curve",               1, NULL,  247 },
     { "days",                1, NULL,  246 },
     { "key",                 1, NULL,  203 },
     { "label",               1, NULL,  207 },
     { "new",                 0, NULL,  'n' },
     { "output-secret-key",   1, NULL,  'o' },
     { "op",                  1, NULL,  202 },
     { "output-public-key",   1, NULL,  202 },
     { "password",            1, NULL,  248 },
     { "req",                 1, NULL,  204 },
     { "to",                  1, NULL,  250 },
     { "random",              1, NULL,  205 },
     { "random-file",         1, NULL,  206 },


   /* это стандартые для всех программ опции */
     { "openssl-style",    0, NULL,   5  },
     { "audit",            1, NULL,   4  },
     { "dont-use-colors",  0, NULL,   3  },
     { "audit-file",       1, NULL,   2  },
     { "help",             0, NULL,   1  },
     { NULL,               0, NULL,   0  },
  };

 /* инициализируем множество параметров по-умолчанию */
  memset( &ki, 0, sizeof( struct key_info ));
  ki.algorithm = NULL;
  ki.oid_of_generator = ak_oid_find_by_name( aktool_default_denerator );
  ki.name_of_file_for_generator = NULL;
  ki.format = asn1_der_format;
  ki.curve = ak_oid_find_by_name( "id-tc26-gost-3410-2012-256-paramSetA" );
  ki.days = 365;

 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "a:nco:", long_options, NULL );
       switch( next_option )
      {
        case  1  :   return aktool_key_help();
        case  2  : /* получили от пользователя имя файла для вывода аудита */
                     aktool_set_audit( optarg );
                     break;
        case  3  : /* установка флага запрета вывода символов смены цветовой палитры */
                     ak_error_set_color_output( ak_false );
                     ak_libakrypt_set_option( "use_color_output", 0 );
                     break;
        case  4  : /* устанавливаем уровень аудита */
                     aktool_log_level = atoi( optarg );
                     break;
        case  5  : /* переходим к стилю openssl */
                     aktool_openssl_compability = ak_true;
                     break;

      /* управляющие команды */
        case 'n' :  work = do_new;
                    break;
        case 'c' :  work = do_cert;
                    break;

     /* устанавливаем имя криптографического алгоритма*/
        case 'a' :  if(( ki.algorithm = ak_oid_find_by_ni( optarg )) == NULL ) {
                      aktool_error(
                        _("using unsupported name or identifier \"%s\" for elliptic curve"),
                                                                                          optarg );
                      printf(
                     _("try \"aktool s --oid algorithm\" for list of all available algorithms\n"));
                     return EXIT_FAILURE;
                    }
                    if( ki.algorithm->mode != algorithm ) {
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

     /* запоминаем упользовательское описание ключа */
        case 207:   memcpy( ki.keylabel, optarg,
                                              ak_min( strlen( optarg ), sizeof( ki.keylabel )-1 ));
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

        case 204: /* --req */
                  #ifdef _WIN32
                    GetFullPathName( optarg, FILENAME_MAX, ki.req_file, NULL );
                  #else
                    realpath( optarg , ki.req_file );
                  #endif
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

     /* передача пароля через командную строку */
        case 248: /* --password */
                   memset( ki.password, 0, sizeof( ki.password ));
                   strncpy( ki.password, optarg, sizeof( ki.password ) -1 );
                   break;

     /* определяем формат выходных данных */
        case 250: /* --to */
                   memset( tmp, 0, sizeof( tmp ));
                   strncpy( tmp, optarg, 3 );
                   for( i = 0; i < sizeof( tmp )-1; i ++ ) tmp[i] = toupper( tmp[i] );

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
                   break;

        default:  /* обрабатываем ошибочные параметры */
                   if( next_option != -1 ) work = do_nothing;
                   break;
       }
   } while( next_option != -1 );
   if( work == do_nothing ) return aktool_key_help();

 /* теперь вызов соответствующей функции */
  switch( work ) {
  case do_new:
    exit_status = aktool_key_new();
    break;

  case do_cert:
    exit_status = aktool_key_certificate();
    break;

  default:
    exit_status = EXIT_FAILURE;
  }

 /* завершаем криптографическую библиотеку */
  ak_libakrypt_destroy();
 return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_new( void )
{
  /* проверяем входые данне */
   if( ki.algorithm == NULL ) {
     aktool_error(
          _("use -a (--algorithm) option and set the cryptographic algorithm name or identifier"));
     return EXIT_FAILURE;
   }

  /* запускаем процедуру генерации ключа или ключевой пары */
   switch( ki.algorithm->engine ) {
    case block_cipher:
    case hmac_function:
      return aktool_key_new_keypair( ak_true, ak_false );

    case sign_function: /* создаем пару ключей */
      return aktool_key_new_keypair( ak_true, ak_true );

   default:
      aktool_error(_("the algorithm %s (%s) is a %s and does not use a secret or public keys"),
                                       ki.algorithm->name[0], ki.algorithm->id[0],
                                             ak_libakrypt_get_engine_name( ki.algorithm->engine ));
      return EXIT_FAILURE;
   }

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- *
 \param create_secret флаг должен установлен для создания секретного ключа
 \param create_pair флаг должен быть установлен для генерации пары асимметричных ключей
 * ----------------------------------------------------------------------------------------------- */
 int aktool_key_new_keypair( bool_t create_secret , bool_t create_pair )
{
  int error = ak_error_ok;
  time_t now = time( NULL );
  char password2[ aktool_password_max_length ];
  ak_pointer key = NULL, generator = NULL;

  if( !create_secret ) return EXIT_FAILURE;
  if( ki.name_of_file_for_generator != NULL ) {
    if(( error = ak_random_create_file( generator = malloc( sizeof( struct random )),
                                               ki.name_of_file_for_generator )) != ak_error_ok ) {
      if( generator ) free( generator );
      return EXIT_FAILURE;
    }
  }
   else
    if(( generator = ak_oid_new_object( ki.oid_of_generator )) == NULL ) return EXIT_FAILURE;

 /* создаем ключ */
  if(( key = ak_oid_new_object( ki.algorithm )) == NULL ) goto lab1;

 /* для асимметричных ключей устанавливаем кривую */
  if( ki.algorithm->engine == sign_function ) {
    if(( error = ak_signkey_set_curve( key, ki.curve->data )) != ak_error_ok ) {
      aktool_error(_("using non applicable elliptic curve (%s)"), ki.curve->name[0] );
      goto lab2;
    }
  }

 /* вырабатываем случайный секретный ключ */
  if(( error = ki.algorithm->func.first.set_key_random( key, generator )) != ak_error_ok ) {
    aktool_error(_("incorrect creation of a random secret key value"));
    goto lab2;
  }

 /* устанавливаем срок действия, в сутках, начиная с текущего момента */
  if(( error = ak_skey_set_validity( key, now, now + ki.days*86400 )) != ak_error_ok ) {
    aktool_error(_("incorrect assigning the validity of secret key"));
    goto lab2;
  }

 /* устанавливаем метку */
  if( strlen( ki.keylabel ) > 0 ) {
    if(( error = ak_skey_set_label( key, ki.keylabel, strlen( ki.keylabel ))) != ak_error_ok ) {
      aktool_error(_("incorrect assigning the label of secret key"));
      goto lab2;
    }
  }

  if( create_pair ) { /* телодвижения для асимметричных ключей */
    struct verifykey vkey;

    /* создаем обобщенное имя владельца ключей */
    if( aktool_key_input_name( key ) != ak_error_ok ) {
      aktool_error(_("incorrect creation of owner's distinguished name"));
      goto lab2;
    }

    /* вырабатываем открытый ключ,
       это позволяет выработать номер открытого ключа, а также присвоить ему имя и ресурс */
    if(( error = ak_verifykey_create_from_signkey( &vkey, key )) != ak_error_ok ) {
      aktool_error(_("incorrect creation of public key"));
      goto lab2;
    }

    if( ki.format == aktool_magic_number ) { /* сохраняем открытый ключ как корневой сертификат */

     /* для корневого (самоподписанного) сертификата обязательно устанавливаем бит keyCertSign */
      if(( ki.opts.keyUsageBits&bit_keyCertSign ) == 0 ) {
        ki.opts.keyUsageBits = ( ki.opts.keyUsageBits&(~bit_keyCertSign ))^bit_keyCertSign;
      }

      ki.format = asn1_pem_format; /* возвращаем необходимое значение */
      if( ak_verifykey_export_to_certificate( &vkey, key, generator,  &ki.opts,
                          ki.op_file, ( strlen( ki.op_file ) > 0 ) ? 0 : sizeof( ki.op_file ),
                                                                     ki.format ) != ak_error_ok ) {
        aktool_error(_("wrong export a public key to certificate %s"), ki.op_file );
        goto lab2;
      } else printf(_("certificate of public key stored in %s\n"), ki.op_file );


    } else { /* сохраняем запрос на сертификат */
        if( ak_verifykey_export_to_request( &vkey, key, generator, ki.op_file,
           ( strlen( ki.op_file ) > 0 ) ? 0 : sizeof( ki.op_file ), ki.format ) != ak_error_ok ) {
          aktool_error(_("wrong export a public key to request %s"), ki.op_file );
          goto lab2;
        } else
            printf(_("public key stored in %s file as certificate's request\n"), ki.op_file );
      }

    ak_verifykey_destroy( &vkey );
  } /* конец if( create_pair ) */

 /* мастерим пароль для сохранения секретного ключа */
  if( strlen( ki.password ) == 0 ) {
    memset( ki.password, 0, sizeof( ki.password ));
    memset( password2, 0, sizeof( password2 ) );
   /* первый раз */
    printf(_("input access password for secret key: "));
    if(( error = ak_password_read( ki.password, sizeof( ki.password ))) != ak_error_ok ) {
      aktool_error(_("incorrect password"));
      goto lab2;
    } else printf("\n");
   /* дублируем */
    printf(_("retype password: "));
    if(( error = ak_password_read( password2, sizeof( password2 ))) != ak_error_ok ) {
      aktool_error(_("incorrect password"));
      goto lab2;
    } else printf("\n");
    if((strlen( ki.password ) != strlen( password2 )) ||
       ( !ak_ptr_is_equal( ki.password, password2, strlen( ki.password )))) {
      aktool_error(_("the passwords don't match"));
      goto lab2;
    }
  }

 /* сохраняем созданный ключ в файле */
  if( ak_skey_export_to_file_with_password(
          key,                           /* ключ */
          ki.password,                 /* пароль */
          strlen( ki.password ), /* длина пароля */
          ki.os_file,      /* если имя не задано,
                     то получаем новое имя файла */
          ( strlen( ki.os_file ) > 0 ) ? 0 : sizeof( ki.os_file ),
          ki.format
     ) != ak_error_ok ) {
     aktool_error(_("wrong export a secret key to file %s"), ki.os_file );
     goto lab2;
  } else {
     /* секретный ключ хорошо хранить в хранилище */
     printf(_("secret key stored in %s\n"), ki.os_file );
    }

 /* удаляем память */
  lab2:
   ak_oid_delete_object( ki.algorithm, key );

  lab1:
   if( ki.name_of_file_for_generator != NULL ) {
     ak_random_destroy( generator );
     free( generator );
   }
    else ak_oid_delete_object( ki.oid_of_generator, generator );

 /* очищаем память */
  memset( password2, 0, sizeof( password2 ));
  memset( &ki, 0, sizeof( struct key_info ));

 return ( error == ak_error_ok ) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_certificate( void )
{
  int error = ak_error_ok;
  struct verifykey vkey;
  struct signkey skey;
  ak_pointer generator = NULL;

  if( strlen( ki.req_file ) == 0 ) {
    aktool_error(_("use --req option and set the name of file with request"));
    return EXIT_FAILURE;
  }
  if( strlen( ki.key_file ) == 0 ) {
    aktool_error(_("use --key option and set the name of file with secret key"));
    return EXIT_FAILURE;
  }

 /* создаем генератор слечайных чисел */
  if( ki.name_of_file_for_generator != NULL ) {
    if(( error = ak_random_create_file( generator = malloc( sizeof( struct random )),
                                               ki.name_of_file_for_generator )) != ak_error_ok ) {
      if( generator ) free( generator );
      return EXIT_FAILURE;
    }
  }
   else
    if(( generator = ak_oid_new_object( ki.oid_of_generator )) == NULL ) return EXIT_FAILURE;

 /* считываем запрос на сертификат */
  if(( error = ak_verifykey_import_from_request( &vkey, ki.req_file )) != ak_error_ok ) {
    aktool_error(_("file %s has incorrect data"), ki.req_file );
    goto lab1;
  }
 /* считываем ключ подписи */
  if(( error = ak_skey_import_from_file( &skey, sign_function, ki.key_file )) != ak_error_ok ) {
    aktool_error(_("file %s has incorrect secret key"), ki.key_file );
    goto lab1;
  }
 /* при необходимости указываем личность подписанта */
  if( skey.name == NULL ) aktool_key_input_name( &skey );

 /* экспортируем открытый ключ в сертификат */
  if(( error = ak_verifykey_export_to_certificate(
                   &vkey,
                   &skey,
                   generator,
                   &ki.opts,
                   ki.op_file, ( strlen( ki.op_file ) > 0 ) ? 0 : sizeof( ki.op_file ),
                   ki.format
     )) != ak_error_ok ) {
    aktool_error(_("wrong export a public key to certificate %s"), ki.op_file );
  } else printf(_("certificate of public key stored in %s\n"), ki.op_file );

  ak_signkey_destroy( &skey );

 lab1:
  ak_verifykey_destroy( &vkey );
  if( ki.name_of_file_for_generator != NULL ) {
    ak_random_destroy( generator );
    free( generator );
  }
   else ak_oid_delete_object( ki.oid_of_generator, generator );

 return error == ak_error_ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_input_name( ak_pointer key )
{
  size_t len = 0;
  char string[256];
  bool_t noname = ak_true;

 /* 0. Выводим стандартное пояснение */
  aktool_key_print_disclaimer();

 /* в короткой форме мы можем запросить флаги
               /co/st/ln/or/ou/sa/cn/su/em/sn */

 /* 1. Country Name */
  ak_snprintf( string, len = sizeof( string ), "RU" );
  if( ak_string_read(_("Country Name (2 letter code)"), string, &len ) == ak_error_ok ) {
   #ifdef AK_HAVE_CTYPE_H
    string[0] = toupper( string[0] );
    string[1] = toupper( string[1] );
   #endif
    string[2] = 0;
    if( len && ( ak_signkey_add_name_string( key,
                                      "country-name", string ) == ak_error_ok )) noname = ak_false;
  }
 /* 2. State or Province */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("State or Province"), string, &len ) == ak_error_ok )
    if( len && ( ak_signkey_add_name_string( key,
                            "state-or-province-name", string ) == ak_error_ok )) noname = ak_false;
 /* 3. Locality */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Locality (eg, city)"), string, &len ) == ak_error_ok )
    if( len && ( ak_signkey_add_name_string( key,
                                     "locality-name", string ) == ak_error_ok )) noname = ak_false;
 /* 4. Organization */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Organization (eg, company)"), string, &len ) == ak_error_ok )
    if( len && ( ak_signkey_add_name_string( key,
                                      "organization", string ) == ak_error_ok )) noname = ak_false;
 /* 5. Organization Unit*/
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Organization Unit"), string, &len ) == ak_error_ok )
    if( len && ( ak_signkey_add_name_string( key,
                                 "organization-unit", string ) == ak_error_ok )) noname = ak_false;
 /* 6. Street Address */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Street Address"), string, &len ) == ak_error_ok )
    if( len && ( ak_signkey_add_name_string( key,
                                    "street-address", string ) == ak_error_ok )) noname = ak_false;
 /* 7. Common Name */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Common Name"), string, &len ) == ak_error_ok )
    if( len && ( ak_signkey_add_name_string( key,
                                       "common-name", string ) == ak_error_ok )) noname = ak_false;
 /* 8. email address */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Email Address"), string, &len ) == ak_error_ok )
    if( len && ( ak_signkey_add_name_string( key,
                                     "email-address", string ) == ak_error_ok )) noname = ak_false;
  if( noname ) {
    aktool_error(
   _("generation of a secret or public keys without any information about owner are not allowed"));
    return ak_error_invalid_value;
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_print_disclaimer( void )
{
  printf(_(" -----\n"
   " You are about to be asked to enter information that will be incorporated\n"
   " into your secret key and certificate request.\n"
   " What you are about to enter is what is called a Distinguished Name or a DN.\n"
   " There are quite a few fields but you can leave some blank.\n"
   " For some fields there will be a default value.\n"
   " If you do not want to provide information just enter a string of one or more spaces.\n"
   " -----\n"));

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_help( void )
{
  printf(
   _("aktool key [options]  - key generation and management functions\n\n"
     "available options:\n"
     " -a, --algorithm         specify the name of the cryptographic algorithm for the new key\n"
     "                         one can use any supported names or identifiers of algorithm\n"
     " -c, --cert              create a public key certificate from a given request\n"
     "     --curve             set the elliptic curve identifier for public keys\n"
     "     --days              set the days count to expiration date of secret or public key\n"
     "     --key               set the secret key to sign the public key certificate\n"
     "     --label             assign the user-defined label to secret key\n"
     " -n, --new               generate a new key or key pair for specified algorithm\n"
     "     --output-public-key set the file name for the new public key request\n"
     " -o, --output-secret-key set the file name for the new secret key\n"
     "     --op                short form of --output-public-key option\n"
     "     --password          specify the password for storing a secret key directly in command line\n"
     "     --random            set the name or identifier of random sequences generator\n"
     "                         the generator will be used to create a new key [ default value is \"%s\" ]\n"
     "     --random-file       set the name of file with random sequence\n"
     "     --req               set the name of request to certificate which would be signed\n"
     "     --to                set the format of output file [ enabled values : der, pem, certificate ]\n\n"
     "options for customizing a public key's certificate:\n"
     "     --ca                use as certificate authority [ enabled values: true, false ]\n"
     "     --path-len          set the maximal length of certificate's chain\n"
     "     --digital-signature use for verifying a digital signatures of user data\n"
     "     --content-commitment\n"
     "     --key-encipherment  use for encipherment of secret keys\n"
     "     --data-encipherment use for encipherment of user data (is not usally used)\n"
     "     --key-agreement     use in key agreement protocols for subject's authentication\n"
     "     --key-cert-sign     use for verifying of public key's certificates\n"
     "     --crl-sign          use for verifying of revocation lists of certificates\n"
  ),
  aktool_default_denerator );
  aktool_print_common_options();

  printf(_("for usage examples try \"man aktool\"\n" ));

 return EXIT_SUCCESS;
}
