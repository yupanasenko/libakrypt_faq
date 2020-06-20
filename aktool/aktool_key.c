/* ----------------------------------------------------------------------------------------------- */
 #include <aktool.h>

/* ----------------------------------------------------------------------------------------------- */
 #define aktool_magic_number    (113)

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_help( void );
 int aktool_key_new( void );
int aktool_key_new_keypair( bool_t , bool_t );
 int aktool_key_certificate( void );
 int aktool_key_print_disclaimer( void );
 int aktool_key_input_name( ak_handle );

/* ----------------------------------------------------------------------------------------------- */
 static struct key_info {
   char *algorithm;
   ak_handle key, vkey;
   char *key_description;
   export_format_t format;
   char *curve;
   size_t days;
   struct certificate_opts opts;
   char password[aktool_max_password_len];

   char ok_file[FILENAME_MAX]; /* сохраняем секретный ключ */
   char op_file[FILENAME_MAX];  /* сохраняем открытый ключ */
   char req_file[FILENAME_MAX];    /* читаем открытый ключ */
   char key_file[FILENAME_MAX];   /* читаем секретный ключ */
 } ki;

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key( int argc, TCHAR *argv[] )
{
#ifdef _WIN32
  unsigned int cp = 0;
#endif
  char tmp[4];
  size_t i = 0;
  int next_option = 0, exit_status = EXIT_FAILURE;
  enum { do_nothing, do_new, do_cert } work = do_nothing;
  struct oid_info oid = { undefined_engine, undefined_mode, NULL, NULL };

  const char *short_options = "a:l:nc";
  const struct option long_options[] = {
   /* сначала уникальные */
     { "algorithm",           1, NULL,  'a' },
     { "cert",                0, NULL,  'c' },
     { "curve",               1, NULL,  247 },
     { "days",                1, NULL,  246 },     
     { "key",                 1, NULL,  203 },
     { "label",               1, NULL,  'l' },
     { "new",                 0, NULL,  'n' },
     { "ok",                  1, NULL,  201 },
     { "output-secret-key",   1, NULL,  201 },
     { "op",                  1, NULL,  202 },
     { "output-public-key",   1, NULL,  202 },
     { "password",            1, NULL,  248 },
     { "req",                 1, NULL,  204 },
     { "to",                  1, NULL,  250 },

    /* флаги использования открытого ключа */
     { "digital-signature",   0, NULL,  190 },
     { "content-commitment",  0, NULL,  191 },
     { "key-encipherment",    0, NULL,  192 },
     { "data-encipherment",   0, NULL,  193 },
     { "key-agreement",       0, NULL,  194 },
     { "key-cert-sign",       0, NULL,  195 },
     { "crl-sign",            0, NULL,  196 },
     { "ca",                  1, NULL,  197 },
     { "path-len",            1, NULL,  198 },

    /* потом общие */
     { "dont-use-colors",     0, NULL,   3  },
     { "audit",               1, NULL,   2  },
     { "help",                0, NULL,   1  },
     { NULL,                  0, NULL,   0  }
  };

 /* инициализируем множество параметров по-умолчанию */
  memset( &ki, 0, sizeof( struct key_info ));
  ki.algorithm = NULL;
  ki.key = ki.vkey = ak_error_wrong_handle;
  ki.key_description = NULL;
  ki.format = asn1_der_format;
  ki.curve = NULL;
  ki.days = 365;
  ki.opts = certificate_default_options;

 /* разбираем опции командной строки */
  do {
    next_option = getopt_long( argc, argv, short_options, long_options, NULL );
    switch( next_option ) {

    /* сначала обработка стандартных опций */
    case   1: return aktool_key_help();

    /* получили от пользователя имя файла для вывода аудита */
    case   2: aktool_set_audit( optarg );
      break;

    /* установка флага запрета вывода символов смены цветовой палитры */
    case   3: ak_libakrypt_set_color_output( ak_false );
      break;

    /* управляющие команды */
    case 'n' :  work = do_new;
      break;
    case 'c' :  work = do_cert;
      break;

    /* устанавливаем имя криптографического алгоритма*/
    case 'a' : ki.algorithm = optarg;
      break;
    /* запоминаем указатель на пользовательское описание ключа */
    case 'l':  ki.key_description =
     #ifdef _WIN32
      _strdup( optarg );
     #else
      strndup( optarg, 128 );
     #endif
      break;

    /* устанавливаем биты для keyUsage и другие параметры сертификата */
    case 190: ki.opts.keyUsageBits ^= bit_digitalSignature;
      break;
    case 191: ki.opts.keyUsageBits ^= bit_contentCommitment;
      break;
    case 192: ki.opts.keyUsageBits ^= bit_keyEncipherment;
      break;
    case 193: ki.opts.keyUsageBits ^= bit_dataEncipherment;
      break;
    case 194: ki.opts.keyUsageBits ^= bit_keyAgreement;
      break;
    case 195: ki.opts.keyUsageBits ^= bit_keyCertSign;
      break;
    case 196: ki.opts.keyUsageBits ^= bit_cRLSign;
      break;
    case 197: /* --ca */
      if( strncmp( optarg, "true", 4 ) == 0 ) ki.opts.ca = ak_true;
       else
	if( strncmp( optarg, "false", 5 ) == 0 ) ki.opts.ca = ak_false;
         else {
                aktool_error(_("%s is not valid value of certificate authority option"), optarg );
                return EXIT_FAILURE;
              }
      break;
    case 198: /* --pathlen */
      if(( ki.opts.pathlenConstraint = atoi( optarg )) > 100 )
        ki.opts.pathlenConstraint = 100;
      break;

    /* устанавливаем имена файлов (в полном, развернутом виде) */
    case 201: /* --ok, --output-secret-key */
     #ifdef _WIN32
      GetFullPathName( optarg, FILENAME_MAX, ki.ok_file, NULL );
     #else
      realpath( optarg , ki.ok_file );
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
      memset( &oid, 0, sizeof( struct oid_info ));
      ak_libakrypt_get_oid( optarg, &oid );
      if(( oid.engine == identifier ) && ( oid.mode == wcurve_params )) ki.curve = optarg;
        else {
              aktool_error(_("%s is not valid identifier for elliptic curve"), optarg );
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
      
    default: /* обрабатываем ошибочные параметры */
      if( next_option != -1 ) work = do_nothing;
      break;
    }
    
  } while( next_option != -1 );
  if( work == do_nothing ) return aktool_key_help();

 /* начинаем работу с криптографическими примитивами */
  if( ak_libakrypt_create( audit ) != ak_true ) {
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }

#ifdef _WIN32
  cp = GetConsoleCP();
  SetConsoleCP( 1251 );
  SetConsoleOutputCP( 1251 );
#endif

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

#ifdef _WIN32
  SetConsoleCP( cp );
  SetConsoleOutputCP( cp );
#endif

  return exit_status;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_new( void )
{
  struct oid_info oid = { undefined_engine, undefined_mode, NULL, NULL };

  /* проверяем входые данне */
   if( ki.algorithm == NULL ) {
     aktool_error(_("use -a (--algorithm) option and set the cryptographic algorithm name or identifier"));
     return EXIT_FAILURE;
   }
   if( ak_libakrypt_get_oid( ki.algorithm, &oid ) != ak_error_ok ) {
     aktool_error(_("%s is not correct name or identifier"), ki.algorithm );
     printf(_("\ntry \"aktool show --oids\" for list all available names and identifiers\n"));
     return EXIT_FAILURE;
   }
   if( oid.mode != algorithm ) {
     aktool_error(_("name %s (%s) is not cryptographic algorithm"), oid.names[0], oid.id );
     printf(_("\ntry \"aktool show --oid algorithm\" for list all available algorithms\n"));
     return EXIT_FAILURE;
   }

  /* запускаем процедуру генерации ключа или ключевой пары */
   switch( oid.engine ) {
    case block_cipher:
    case hmac_function:
      return aktool_key_new_keypair( ak_true, ak_false );

    case sign_function: /* создаем пару ключей */
      return aktool_key_new_keypair( ak_true, ak_true );

    case verify_function:  /* создаем (должно быть, повторно) открытый ключ из секретного */
      //      return aktool_key_new_keypair( ak_false, ak_true );
      
    default:
      aktool_error(_("the algorithm %s (%s) is a %s and does not use a secret or public keys"),
                                oid.names[0], oid.id, ak_libakrypt_get_engine_name( oid.engine ));
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
  time_t now = time( NULL );
  char password2[aktool_max_password_len];
  int exitcode = EXIT_FAILURE, error = ak_error_ok;

  if( !create_secret && !create_pair ) return EXIT_FAILURE;
  if( !create_secret && create_pair ) return EXIT_FAILURE;
  
 /* создаем дескриптор секретного ключа с пользовательским описанием */
  if(( ki.key = ak_handle_new( ki.algorithm, ki.key_description )) == ak_error_wrong_handle ) {
    aktool_error(_("incorrect creation of a secret key for %s algorithm"), ki.algorithm );
    return EXIT_FAILURE;
  }

 /* если пользователем задана эллиптическая кривая, то устанавливаем ее
    важно, что кривая должна быть определена до момента установки ключевого значения */
  if( create_pair && ( ki.curve != NULL )) {
    if( ak_handle_set_curve( ki.key, ki.curve ) != ak_error_ok ) {
      aktool_error(_("using non applicable elliptic curve"));
      goto labex;
    }
   }

 /* теперь вырабатываем случайный секретный ключ */
  if( ak_handle_set_key_random( ki.key ) != ak_error_ok ) {
    aktool_error(_("incorrect creation of a random secret key value"));
    goto labex;
  }

 /* срок действия, в сутках, начиная с текущего момента */
  ak_handle_set_validity( ki.key, now, now + ki.days*86400 );

  if( create_pair ) {
   /* нужно создать обобщенное имя владельца ключей */
    if( aktool_key_input_name( ki.key ) != ak_error_ok ) {
      aktool_error(_("incorrect creation of owner's distinguished name"));
      goto labex;
    }

   /* вырабатываем открытый ключ,
      это позволяет выработать номер открытого ключа, а также присвоить ему имя и ресурс */
    if(( ki.vkey = ak_handle_new_from_signkey( ki.key, NULL )) == ak_error_wrong_handle ) {
      aktool_error(_("incorrect creation of public key value"));
      goto labex;
    }

    if( ki.format == aktool_magic_number ) { /* сохраняем открытый ключ как корневой сертификат
         для корневого (самоподписанного) сертификата обязательно устанавливаем бит keyCertSign */
      
      if(( ki.opts.keyUsageBits&bit_keyCertSign ) == 0 ) {
        ki.opts.keyUsageBits = ( ki.opts.keyUsageBits&(~bit_keyCertSign ))^bit_keyCertSign;
      }

      ki.format = asn1_pem_format; /* возвращаем необходимое значение */
      if( ak_handle_export_to_certificate( ki.vkey, ki.key, &ki.opts, ki.op_file,
           ( strlen( ki.op_file ) > 0 ) ? 0 : sizeof( ki.op_file ), ki.format ) != ak_error_ok ) {
        aktool_error(_("wrong export a public key to certificate %s"), ki.op_file );
        goto labex;
      } else printf(_("certificate of public key stored in %s\n"), ki.op_file );

    } else { /* сохраняем запрос на сертификат */
       if( ak_handle_export_to_request( ki.vkey, ki.key, ki.op_file,
           ( strlen( ki.op_file ) > 0 ) ? 0 : sizeof( ki.op_file ), ki.format ) != ak_error_ok ) {
         aktool_error(_("wrong export a public key to request %s"), ki.op_file );
         goto labex;
       } else printf(_("public key stored in %s (as certificate request)\n"), ki.op_file );
      }
  } /* конец if( pair ) */

 /* мастерим пароль для сохранения секретного ключа */
  if( strlen( ki.password ) == 0 ) {
    memset( ki.password, 0, sizeof( ki.password ));
    memset( password2, 0, sizeof( password2 ) );
   /* первый раз */
    printf(_("input access password for secret key: "));
    if(( error = ak_password_read( ki.password, sizeof( ki.password ))) != ak_error_ok ) {
      aktool_error(_("incorrect password"));
      goto labex;
    } else printf("\n");
   /* дублируем */
    printf(_("retype password: "));
    if(( error = ak_password_read( password2, sizeof( password2 ))) != ak_error_ok ) {
      aktool_error(_("incorrect password"));
      goto labex;
    } else printf("\n");
    if((strlen( ki.password ) != strlen( password2 )) ||
       ( !ak_ptr_is_equal( ki.password, password2, strlen( ki.password )))) {
      aktool_error(_("the passwords don't match"));
      goto labex;
    }
  }

 /* сохраняем секретный ключ в файловый контейнер */
  if( ak_handle_export_to_file_with_password( ki.key, ki.password, strlen( ki.password ),
					      ki.ok_file, ( strlen( ki.ok_file ) > 0 ) ? 0 : sizeof( ki.ok_file ),
                                                                    ki.format ) != ak_error_ok ) {
     aktool_error(_("wrong export a secret key to file %s"), ki.ok_file );
     goto labex;
  } else {
     /* секретный ключ хорошо хранить в хранилище */
     printf(_("secret key stored in %s\n"), ki.ok_file );
    }

  exitcode = EXIT_SUCCESS;
  labex:
    memset( password2, 0, sizeof( password2 ));
    memset( ki.password, 0, sizeof( ki.password ));
    if( ki.vkey != ak_error_wrong_handle ) ak_handle_delete( ki.vkey );
    ak_handle_delete( ki.key );

 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_certificate( void )
{
  /* считываем запрос на сертификат, который будет подписываться */
  
  /* считываем секретный ключ */
  
  return EXIT_FAILURE;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_input_name( ak_handle handle )
{
  size_t len = 0;
  char string[256];
  bool_t noname = ak_true;

 /* 0. Выводим стандартное пояснение */
  aktool_key_print_disclaimer();

 /* 1. Country Name */
  ak_snprintf( string, len = sizeof( string ), "RU" );
  if( ak_string_read(_("Country Name (2 letter code)"), string, &len ) == ak_error_ok ) {
   #ifdef LIBAKRYPT_HAVE_CTYPE_H
    string[0] = toupper( string[0] );
    string[1] = toupper( string[1] );
   #endif
    string[2] = 0;
    if( len && ( ak_handle_add_name_string( handle,
                                      "Country Name", string ) == ak_error_ok )) noname = ak_false;
  }
 /* 2. State or Province */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("State or Province"), string, &len ) == ak_error_ok )
    if( len && ( ak_handle_add_name_string( handle,
                            "State Or Province Name", string ) == ak_error_ok )) noname = ak_false;
 /* 3. Locality */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Locality (eg, city)"), string, &len ) == ak_error_ok )
    if( len && ( ak_handle_add_name_string( handle,
                                     "Locality Name", string ) == ak_error_ok )) noname = ak_false;
 /* 4. Organization */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Organization (eg, company)"), string, &len ) == ak_error_ok )
    if( len && ( ak_handle_add_name_string( handle,
                                      "Organization", string ) == ak_error_ok )) noname = ak_false;
 /* 5. Organization Unit*/
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Organization Unit"), string, &len ) == ak_error_ok )
    if( len && ( ak_handle_add_name_string( handle,
                                 "Organization Unit", string ) == ak_error_ok )) noname = ak_false;
 /* 6. Street Address */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Street Address"), string, &len ) == ak_error_ok )
    if( len && ( ak_handle_add_name_string( handle,
                                    "Street Address", string ) == ak_error_ok )) noname = ak_false;
 /* 7. Common Name */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Common Name"), string, &len ) == ak_error_ok )
    if( len && ( ak_handle_add_name_string( handle,
                                       "Common Name", string ) == ak_error_ok )) noname = ak_false;
 /* 8. email address */
  memset( string, 0, len = sizeof( string ));
  if( ak_string_read(_("Email Address"), string, &len ) == ak_error_ok )
    if( len && ( ak_handle_add_name_string( handle,
                                     "Email Address", string ) == ak_error_ok )) noname = ak_false;
  if( noname ) {
    aktool_error(_("generation of a secret or public keys without any information about owner are not allowed"));
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
     " -l, --label             assign the user-defined label to secret key\n"
     " -n, --new               generate a new key or key pair for specified algorithm\n"
     "     --ok                short form of --output-secret-key option\n"
     "     --output-secret-key set the file name for the new secret key\n"
     "     --op                short form of --output-public-key option\n"
     "     --output-public-key set the file name for the new public key request\n"
     "     --password          specify the password for storing a secret key directly in command line\n"
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
  ));
  aktool_print_common_options();

  printf(_("for usage examples try \"man aktool\"\n" ));
  
 return EXIT_SUCCESS;
}


/* ----------------------------------------------------------------------------------------------- */
/*                                                                                   aktool_key.c  */
/* ----------------------------------------------------------------------------------------------- */
