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
 int aktool_key_verify_key( int argc , char *argv[] );

/* ----------------------------------------------------------------------------------------------- */
 int aktool_key( int argc, char *argv[] )
{
  int next_option = 0, exit_status = EXIT_FAILURE;
  enum { do_nothing, do_new, do_show, do_verify, do_cert } work = do_nothing;

 /* параметры, запрашиваемые пользователем */
  const struct option long_options[] = {
   /* сначала уникальные */
     { "algorithm",           1, NULL,  'a' },
     { "new",                 0, NULL,  'n' },
     { "show",                1, NULL,  's' },
     { "output-secret-key",   1, NULL,  'o' },
     { "verify",              0, NULL,  'v' },
     { "cert",                1, NULL,  'c' },
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
       next_option = getopt_long( argc, argv, "hns:a:o:t:vc:", long_options, NULL );
       switch( next_option )
      {
        aktool_common_functions_run( aktool_key_help );

      /* управляющие команды */
        case 'v' : /* --verify */
                    work = do_verify;
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
      break;

    case do_show:
      break;

    case do_verify:
      exit_status = aktool_key_verify_key( argc, argv );
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
/*                        проверка подписи под запросами и сертификатами                           */
/* ----------------------------------------------------------------------------------------------- */
 static int aktool_key_verify_print_request( ak_verifykey vkey, ak_request_opts reqopt )
{  
  ak_asn1 lst = NULL;
  size_t i = 0, ts = ak_hash_get_tag_size( &vkey->ctx );

  printf(_("Certificate's request\n"));
  printf(_("  subject: %s\n"), ak_tlv_get_string_from_global_name( vkey->name, "2.5.4.3", NULL ));
  printf(_("  global name:\n"));

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
          ak_asn1_next( sq );
          printf("    %s (%s): %s\n",
                                    oid->name[1], _( oid->name[0] ), sq->current->data.primitive );
        }
    } while( ak_asn1_next( lst ));
  }

 /* информация о ключе */
  printf(_("  public key:\n    x:  "));
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
                 if( !ki.quiet ) printf(_("verified: Ok\n"));
                 ak_verifykey_destroy( &vkey ); /* не забыть убрать за собой */
                 continue;
              case ak_error_not_equal_data:
                 if( !ki.quiet ) printf(_("verified: No\n"));
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
