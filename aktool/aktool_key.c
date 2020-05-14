/* ----------------------------------------------------------------------------------------------- */
 #include <aktool.h>

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_help( void );
 int aktool_key_new( void );
 int aktool_key_new_keypair( void );

/* ----------------------------------------------------------------------------------------------- */
 static struct key_info {
  char *algorithm;
  ak_handle key, vkey;
  char *key_description;
  export_format_t format;
  char *curve;
  char password[aktool_max_password_len];
  char keyfile[FILENAME_MAX]; /* имя файла для секретного ключа */
  char csrfile[FILENAME_MAX]; /* имя файла для открытого ключа */
 }
  ki = {
     NULL,
     ak_error_wrong_handle,
     ak_error_wrong_handle,
     NULL,
     asn1_der_format,
     NULL,
     "",
     "",
     ""
 };

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key( int argc, TCHAR *argv[] )
{
  int next_option = 0, exit_status = EXIT_FAILURE;
  enum { do_nothing, do_new } work = do_nothing;
  struct oid_info oid = { undefined_engine, undefined_mode, NULL, NULL };

  const struct option long_options[] = {
   /* сначала уникальные */
     { "algorithm",           1, NULL,  'a' },
     { "outkey",              1, NULL,  'o' },
     { "label",               1, NULL,  'l' },
     { "new",                 0, NULL,  255 },
     { "to",                  1, NULL,  250 },
     { "password",            1, NULL,  248 },
     { "curve",               1, NULL,  220 },
     { "pubkey",              1, NULL,  210 },

    /* потом общие */
     { "dont-use-colors",     0, NULL,   3 },
     { "audit",               1, NULL,   2  },
     { "help",                0, NULL,   1  },
     { NULL,                  0, NULL,   0  }
  };


 /* разбираем опции командной строки */
  do {
       next_option = getopt_long( argc, argv, "a:o:l:", long_options, NULL );
       switch( next_option )
      {
       /* сначала обработка стандартных опций */
         case   1 : return aktool_key_help();

         case   2 : /* получили от пользователя имя файла для вывода аудита */
                     aktool_set_audit( optarg );
                     break;
         case   3 : /* установка флага запрета вывода символов смены цветовой палитры */
                     ak_libakrypt_set_color_output( ak_false );

       /* теперь опции специфичные для key */
         case 255:  work = do_new;
                    break;

       /* определяем формат выходных данных (--to) */
         case 250:  if(( strncmp( optarg, "der", 3 ) == 0 ) || ( strncmp( optarg, "DER", 3 ) == 0 ))
                      ki.format = asn1_der_format;
                     else
                      if(( strncmp( optarg, "pem", 3 ) == 0 ) || ( strncmp( optarg, "PEM", 3 ) == 0 ))
                        ki.format = asn1_pem_format;
                       else {
                         aktool_error(_("%s is not valid format of output data"), optarg );
                         return EXIT_FAILURE;
                       }
                    break;

       /* передача пароля через коммандную строку */
         case 248 :  memset( ki.password, 0, sizeof( ki.password ));
                     strncpy( ki.password, optarg, sizeof( ki.password ) -1 );
                     break;

       /* проверяем идентификатор кривой */
         case 220:  memset( &oid, 0, sizeof( struct oid_info ));
                    ak_libakrypt_get_oid( optarg, &oid );
                    if(( oid.engine == identifier ) && ( oid.mode == wcurve_params )) ki.curve = optarg;
                     else {
                         aktool_error(_("%s is not valid identifier for elliptic curve"), optarg );
                         return EXIT_FAILURE;
                     }
                    break;

       /* устанавливаем имя криптографического алгоритма*/
         case 'a' : ki.algorithm = optarg;
                    break;
       /* запоминаем указатель на пользовательское описание ключа */
         case 'l':  ki.key_description = optarg;
                    break;
       /* устанавливаем имя файла для сохранения секретного ключа */
         case 'o' :
                    #ifdef _WIN32
                      GetFullPathName( optarg, FILENAME_MAX, ki.keyfile, NULL );
                     #else
                       realpath( optarg , ki.keyfile );
                     #endif
                    break;
       /* устанавливаем имя файла для сохранения открытого ключа */
         case 210 :
                    #ifdef _WIN32
                      GetFullPathName( optarg, FILENAME_MAX, ki.csrfile, NULL );
                     #else
                       realpath( optarg , ki.csrfile );
                     #endif
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

     default:
       exit_status = EXIT_FAILURE;
  }

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
     printf(_("\ntry \"aktool show --oids\" for list all available names/identifiers\n"));
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
      break;

    case sign_function: /* создаем пару ключей */
      return aktool_key_new_keypair();

    case verify_function:  /* создаем (должно быть, повторно) открытый ключ из секретного */
      break;

    default:
      aktool_error(_("the algorithm %s (%s) does not use a secret or public keys"),
                                                                            oid.names[0], oid.id );
      return EXIT_SUCCESS;
   }

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вырабатывает пару секретный/открытый ключ и сохраняет ключи на диск. */
/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_new_keypair( void )
{
  char password2[aktool_max_password_len];
  int exitcode = EXIT_FAILURE, error = ak_error_ok;

 /* создаем дескриптор секретного ключа с пользовательским описанием */
  if(( ki.key = ak_handle_new( ki.algorithm, ki.key_description )) == ak_error_wrong_handle ) {
    aktool_error(_("wrong creation of a secret key for %s algorithm"), ki.algorithm );
    return EXIT_FAILURE;
  }
 /* если пользователем задана эллиптическая кривая, то устанавливаем ее */
  if( ki.curve ) {
    if( ak_handle_set_curve( ki.key, ki.curve ) != ak_error_ok ) {
      aktool_error(_("using not applicable elliptic curve"));
      goto labex;
    }
  }

 /* теперь вырабатываем случайный секретный ключ */
  if( ak_handle_set_key_random( ki.key ) != ak_error_ok ) {
    aktool_error(_("incorrect creation of secret key value"));
    goto labex;
  }
 /* нужно указать имя владельца, срок действия */

 /* вырабатываем открытый ключ,
    это позволяет выработать номер открытого ключа, а также присвоить ему имя и ресурс */
  if(( ki.vkey = ak_handle_new_from_signkey( ki.key, NULL )) == ak_error_wrong_handle ) {
    aktool_error(_("incorrect creation of public key value"));
    goto labex;
  }

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

  aktool_error("i know the pass -> %s", ki.password );
 // нужна опция сохранения ключа в базу в случае ее отсутствия

 /* сохраняем секретный ключ в файловый контейнер */
  if( ak_handle_export_to_file_with_password( ki.key, ki.password, strlen( ki.password ),
                       ki.keyfile, ( strlen( ki.keyfile ) > 0 ) ? 0 : sizeof( ki.keyfile ),
                                                                ki.format ) != ak_error_ok ) {
     aktool_error(_("wrong export a secret key to file %s"), ki.keyfile );
     goto labex;
  } else
     printf(_("secret key stored in %s file\n"), ki.keyfile );

  if( ak_handle_export_to_request( ki.vkey, ki.key, ki.csrfile,
      ( strlen( ki.csrfile ) > 0 ) ? 0 : sizeof( ki.csrfile ), ki.format ) != ak_error_ok ) {
     aktool_error(_("wrong export a public key to request %s"), ki.csrfile );
     goto labex;
  } else
     printf(_("public key stored in %s file\n"), ki.csrfile );

 /* сохраняем открытый ключ
     - в запрос
     - в самоподписанный сертификат
 */



  exitcode = EXIT_SUCCESS;

  labex:
    memset( password2, 0, sizeof( password2 ));
    memset( ki.password, 0, sizeof( ki.password ));
    if( ki.vkey != ak_error_wrong_handle ) ak_handle_delete( ki.vkey );
    ak_handle_delete( ki.key );

 return exitcode;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key_help( void )
{
  printf(_("aktool key [options]  - key generation and management functions\n\n"));
  printf(_("available options:\n"));
  printf(_(" -a, --algorithm <ni>    set the cryptographic algorithm for a new key, where \"ni\" is name or identifier\n" ));
  printf(_("     --curve <ni>        set the elliptic curve identifier for public keys\n"));
  printf(_(" -l, --label <text>      assign the user-defined label to secret key\n" ));
  printf(_("     --new               generate a new key or key pair for selected algorithm\n" ));
  printf(_(" -o, --outkey <file>     set the name of output file for secret key\n" ));
  printf(_("     --password <pass>   set the password for storing a secret key directly in command line\n"));
  printf(_("     --pubkey <file>     set the name of output file for public key request or certificate\n" ));
  printf(_("     --to <format>       set the format of output file [ enabled values : der, pem ]\n" ));

 return aktool_print_common_options();
}
