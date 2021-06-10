/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2021 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл akrypt.c                                                                                  */
/*  - содержит реализацию консольной утилиты, иллюстрирующей возможности библиотеки libakrypt      */
/* ----------------------------------------------------------------------------------------------- */
 #include <aktool.h>
#ifdef _MSC_VER
 #include <strsafe.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 aktool_ki_t ki = {
   .aktool_log_level = ak_log_none, /* аудит не выполняется */
   .aktool_openssl_compability = ak_false,    /* совместимость с openssl не предусматривается */
   .aktool_hex_password_input = ak_false,    /* пароли вводятся как символы текста */
   .verbose = ak_false,    /* вывод подробной информации/справки  */
   .quiet = ak_false,
   .method = NULL,
   .oid_of_generator = NULL,
   .name_of_file_for_generator = NULL,
   .generator = NULL,
   .oid_of_target = NULL,
   .format = asn1_der_format,
   .target_undefined = ak_false,
   .curve = NULL,
   .days = 365, /* срок действия ключа (в сутках) */
   .field = ak_galois256_size,
   .size = 512,
   .keylabel = NULL, /* указатель на внешнюю область памяти */
   .lenuser = 0,
   .leninpass = 0,
   .lenoutpass = 0,
   .userid = "",
   .inpass = "",
   .outpass = "",
   .audit_filename = "", /* имя файла аудита не определено */
   .os_file = "", /* выход, открытый ключ */
   .op_file = "", /* выход, секретный ключ */
   .key_file = "", /* вход, секретный ключ */
   .pubkey_file = "", /* вход, открытый ключ */
   .capubkey_file = "" /* вход, открырый ключ УЦ */
 };

/* ----------------------------------------------------------------------------------------------- */
/* функция, реализующая аудит */
 ak_function_log *audit =
#ifdef _WIN32
 aktool_audit_function;
#else
 ak_function_log_syslog;
#endif

#ifdef _WIN32
 unsigned int aktool_console_page = 0;
#endif

/* ----------------------------------------------------------------------------------------------- */
 int main( int argc, tchar *argv[] )
{
 /* определение переменных, используемых для указания времени старта программы */
 #ifdef _WIN32
  time_t ptime;
  TCHAR homepath[FILENAME_MAX]
   #ifdef _MSC_VER
     , buffer[64]
   #endif
   ;
 #endif
 /* попытка русификации программы для unix-like операционных систем */
 #ifdef AK_HAVE_LIBINTL_H
 /* обрабатываем настройки локали
    при инсталляции файл aktool.mo должен помещаться в /usr/share/locale/ru/LC_MESSAGES
    (однако, при использовании bsd-like адрес может быть другим) */
  #ifdef AK_HAVE_LOCALE_H
   setlocale( LC_ALL, "" );
  #endif
  bindtextdomain( "aktool", "/usr/share/locale/" );
  textdomain( "aktool" );
 #endif

 /* проверяем, что пользователем должна быть задана команда */
  if( argc < 2 ) return aktool_litehelp();

 /* проверяем флаги вывода справочной информации */
  if( aktool_check_command( "-h", argv[1] )) return aktool_help();
  if( aktool_check_command( "--help", argv[1] )) return aktool_help();
  if( aktool_check_command( "/?", argv[1] )) return aktool_help();
  if( aktool_check_command( "--version", argv[1] )) return aktool_version();

 #ifdef _WIN32
  if( ak_libakrypt_get_home_path( homepath, FILENAME_MAX ) == ak_error_ok ) {
    ak_snprintf( ki.audit_filename, sizeof( ki.audit_filename ),
                                                  "%s\\.config\\libakrypt\\aktool.log", homepath );
    remove( ki.audit_filename );
    ak_log_set_function( audit = aktool_audit_function );

   #ifdef _MSC_VER
    _time64( &ptime );
    _tctime64_s( buffer, sizeof( buffer ), &ptime );
    ak_snprintf( homepath, FILENAME_MAX, "%s started at %s", argv[0], buffer );
   #else
     ptime = time( NULL );
     ak_snprintf( homepath, FILENAME_MAX, "%s started at %s", argv[0], ctime( &ptime ));
   #endif
    ak_log_set_message( homepath );
  }
 #endif

 /* выполняем команду пользователя */
  if( aktool_check_command( "s", argv[1] )) return aktool_show( argc, argv );
  if( aktool_check_command( "show", argv[1] )) return aktool_show( argc, argv );
  if( aktool_check_command( "a", argv[1] )) return aktool_asn1( argc, argv );
  if( aktool_check_command( "asn1parse", argv[1] )) return aktool_asn1( argc, argv );
  if( aktool_check_command( "test", argv[1] )) return aktool_test( argc, argv );
  if( aktool_check_command( "k", argv[1] )) return aktool_key( argc, argv );
  if( aktool_check_command( "key", argv[1] )) return aktool_key( argc, argv );
  if( aktool_check_command( "i", argv[1] )) return aktool_icode( argc, argv );
  if( aktool_check_command( "icode", argv[1] )) return aktool_icode( argc, argv );
  if( aktool_check_command( "e", argv[1] )) return aktool_encrypt( argc, argv, do_encrypt );
  if( aktool_check_command( "encrypt", argv[1] )) return aktool_encrypt( argc, argv, do_encrypt );
  if( aktool_check_command( "d", argv[1] )) return aktool_encrypt( argc, argv, do_decrypt );
  if( aktool_check_command( "decrypt", argv[1] )) return aktool_encrypt( argc, argv, do_decrypt );

 /* ничего не подошло, выводим сообщение об ошибке */
  ak_log_set_function( ak_function_log_stderr );
  ak_error_message_fmt( ak_error_undefined_function,
                                                 __func__, _("undefined command \"%s\""), argv[1] );
 return EXIT_FAILURE;
}

/* ----------------------------------------------------------------------------------------------- */
/*                         реализация функций обработки команд пользователя                        */
/* ----------------------------------------------------------------------------------------------- */
 bool_t aktool_check_command( const char *comm, tchar *argv )
{
 size_t len = strlen( comm );

  if( strlen( argv ) != len ) return ak_false;
  if( strncmp( comm, argv, len )) return ak_false;
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/* вывод сообщений в заданный пользователем файл, а также в стандартный демон вывода сообщений */
 int aktool_audit_function( const char *message )
{
  FILE *fp = fopen( ki.audit_filename, "a+" );
   /* функция выводит сообщения в заданный файл */
    if( !fp ) return ak_error_open_file;
    fprintf( fp, "%s\n", message );
#if defined(__unix__) || defined(__APPLE__)
    ak_function_log_syslog( message ); /* все действия дополнительно дублируются в syslog */
#endif
    if( fclose(fp) == EOF ) return ak_error_access_file;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 void aktool_set_audit( tchar *message )
{
  if( ak_ptr_is_equal( "stderr", message, 6 )) {
       audit = ak_function_log_stderr; /* если задан stderr, то используем готовую функцию */
  } else {
            if( strlen( message ) > 0 ) {
              memset( ki.audit_filename, 0, sizeof( ki.audit_filename ));
              strncpy( ki.audit_filename, message, sizeof( ki.audit_filename )-1 );
              audit = aktool_audit_function;
            }
         }
}

/* ----------------------------------------------------------------------------------------------- */
 void aktool_error( const char *format, ... )
{
  va_list args;
  int result = 0;
  char string[1024];

  va_start( args, format );
 #ifdef _MSC_VER
  #if _MSC_VER > 1310
    result = _vsnprintf_s( string, sizeof( string ), sizeof( string ), format, args );
  #else
    result = _vsnprintf( string, sizeof( string ), format, args );
  #endif
 #else
  result = vsnprintf( string, sizeof( string ), format, args );
 #endif
  va_end( args );

 if(( result >= 0 ) && ( !ki.quiet )) /* выводим сообщение только, если нет режима тишины */
   printf(_("%serror%s: %s\n"), ak_error_get_start_string(), ak_error_get_end_string(), string );
}

/* ----------------------------------------------------------------------------------------------- */
 bool_t aktool_create_libakrypt( void )
{
  ak_int64 number;

 /* инициализируем библиотеку */
  if( ak_libakrypt_create( audit ) != ak_true ) {
    ak_libakrypt_destroy();
    aktool_error(_("incorrect initialization of libakrypt library"));
    return ak_false;
  }
 /* устанавливаем уровень аудита */
  ak_log_set_level( ki.aktool_log_level );

 /* применяем флаг совместимости с openssl */
  number = ak_libakrypt_get_option_by_name( "openssl_compability ");
  if(( number != ak_error_wrong_option ) && ( ki.aktool_openssl_compability != number ))
    ak_libakrypt_set_openssl_compability( ki.aktool_openssl_compability );

#ifdef _WIN32
  aktool_console_page = GetConsoleCP();
  SetConsoleCP( 65001 );
  SetConsoleOutputCP( 65001 ); /*  SetConsoleCP( 1251 ); SetConsoleOutputCP( 1251 ); */
#endif

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_destroy_libakrypt( void )
{
 #ifdef _WIN32
  SetConsoleCP( aktool_console_page );
  SetConsoleOutputCP( aktool_console_page );
 #endif
 return ak_libakrypt_destroy();
}


/* ----------------------------------------------------------------------------------------------- */
 int aktool_print_gettext( const char *message )
{
  if( message ) fprintf( stdout, "%s", _( message ));
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                            функции генерации ключевой информации                                */
/* ----------------------------------------------------------------------------------------------- */
 ak_random aktool_key_new_generator( void )
{
  ak_random generator = NULL;

  if( ki.name_of_file_for_generator != NULL ) {
    if( ak_random_create_file( generator = malloc( sizeof( struct random )),
                                                ki.name_of_file_for_generator ) != ak_error_ok ) {
      if( generator ) free( generator );
      return NULL;
    }
    if( ki.verbose ) printf(_("used a file with random data: %s\n"),
                                                                  ki.name_of_file_for_generator );
  }
   else {
    if(( generator = ak_oid_new_object( ki.oid_of_generator )) == NULL ) return NULL;
    if( ki.verbose ) printf(_("used a random number generator: %s\n"),
                                                                    ki.oid_of_generator->name[0] );
   }

 return generator;
}

/* ----------------------------------------------------------------------------------------------- */
 void aktool_key_delete_generator( ak_random generator )
{
   if( ki.name_of_file_for_generator != NULL ) {
     ak_random_destroy( generator );
     free( generator );
   }
    else ak_oid_delete_object( ki.oid_of_generator, generator );
}

/* ----------------------------------------------------------------------------------------------- */
/*                                    Функции ввода ключей                                         */
/* ----------------------------------------------------------------------------------------------- */

/* ----------------------------------------------------------------------------------------------- */
/*! Эта функция используется перед экспортом ключа */
 ssize_t aktool_key_load_user_password_twice( char *password, const size_t pass_size )
{
  int error = ak_error_ok;
  ssize_t passlen = 0, passlen2 = 0;
  char buffer[1 + ( aktool_password_max_length << 1 )], password2[ aktool_password_max_length ];

 /* формируем пароль с первой попытки */
  fprintf( stdout, _("input password"));
   if( ki.aktool_hex_password_input ) fprintf( stdout, _(" [as hexademal string]"));
  fprintf( stdout, ": "); fflush( stdout );
  memset( buffer, 0, sizeof( buffer ));
  passlen = ak_password_read( buffer, sizeof( buffer ));
  fprintf( stdout, "\n" );
  if( passlen < 1 ) {
    aktool_error(_("password zero length"));
    return ak_error_wrong_length;
  }

  memset( password, 0, pass_size );
  if( ki.aktool_hex_password_input ) {
    if(( error = ak_hexstr_to_ptr( buffer, password, pass_size -1, ak_false )) == ak_error_ok )
      passlen = ak_min( pass_size -1, strlen( buffer )%2 + ( strlen( buffer ) >> 1 ));
     else passlen = 0;
    /* как минимум один последний октет password будет равен нулю */
  }
   else memcpy( password, buffer, passlen = ak_min( pass_size -1, strlen( buffer )));

  if( !passlen ) {
    aktool_error(_("password has zero length"));
    return passlen;
  }

 /* теперь считываем пароль второй раз и проверяем совпадение */
  printf(_("retype password"));
   if( ki.aktool_hex_password_input ) fprintf( stdout, _(" [as hexademal string]"));
  fprintf( stdout, ": "); fflush( stdout );
  memset( buffer, 0, sizeof( buffer ));
  passlen2 = ak_password_read( buffer, sizeof( buffer ));
  fprintf( stdout, "\n" );
  if( passlen < 1 ) {
    aktool_error(_("password zero length"));
    return ak_error_wrong_length;
  }

  memset( password2, 0, pass_size );
  if( ki.aktool_hex_password_input ) {
    if(( error = ak_hexstr_to_ptr( buffer, password2, pass_size -1, ak_false )) == ak_error_ok )
      passlen2 = ak_min( pass_size -1, strlen( buffer )%2 + ( strlen( buffer ) >> 1 ));
     else passlen2 = 0;
    /* как минимум один последний октет password будет равен нулю */
  }
   else memcpy( password2, buffer, passlen2 = ak_min( pass_size -1, strlen( buffer )));

  if(( passlen != passlen2 ) ||
     ( !ak_ptr_is_equal( password, password2, passlen ))) {
      aktool_error(_("the passwords don't match"));
      passlen = ak_error_not_equal_data;
    }

  memset( buffer, 0, sizeof( buffer ));
  memset( password2, 0, sizeof( password2 ));

 return passlen;
}


/* ----------------------------------------------------------------------------------------------- */
/*                                 реализация вывода справки                                       */
/* ----------------------------------------------------------------------------------------------- */
 int aktool_litehelp( void )
{
  printf(_("aktool - crypto utility based on libakrypt library (version: %s)\n\n"),
                                                                          ak_libakrypt_version( ));
  printf(_("try \"aktool --help\" to get more information\n"));

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_version( void )
{
  printf(_("version: %s [compiled by %s, version: %s, date: %s at %s]\n"),
               ak_libakrypt_version(), LIBAKRYPT_COMPILER_NAME, __VERSION__, __DATE__, __TIME__ );
 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_print_common_options( void )
{
  printf(
   _("\ncommon aktool options:\n"
     "     --audit             set the audit level [ enabled values : 0 (none), 1 (standard), 2 (max) ]\n"
     "     --audit-file        set the output file for errors and libakrypt audit system messages\n"
     "     --dont-use-colors   do not use the highlighting of output data\n"
     "     --help              show this information\n"
     "     --hex-input         read characters from terminal or console as hexademal numbers\n"
     "     --openssl-style     use non-standard variants of some crypto algorithms, as in openssl library\n"
     "     --quiet             not to display any information and use only the return code\n"
     "     --verbose           show the additional information\n\n"));

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_help( void )
{
  printf(_("aktool - crypto utility based on libakrypt library (version: %s)\n"),
                                                                          ak_libakrypt_version( ));
  printf(_("usage:\n"));
  printf(_("  aktool command [options] [files]\n\n"));
  printf(_("available commands (in short and long forms):\n"));
  printf(_("  a, asn1parse  -  decode and print the ASN.1 data\n"));
  printf(_("  i, icode      -  calculate or check integrity codes\n"));
  printf(_("  k, key        -  key generation and management functions\n"));
  printf(_("  s, show       -  show useful information\n"));
  printf(_("     test       -  run performance and correct operation tests\n\n"));
  printf(_("also try:\n"));
  printf(_("  \"aktool command --help\" to get information about command options\n"));
  printf(_("  \"aktool --version\" to get version of aktool\n"));
  printf(_("  \"man aktool\" to get more information about aktool and useful examples\n\n"));
  printf(_("aktool compiled by %s, version: %s (%s at %s)\n"),
                                         LIBAKRYPT_COMPILER_NAME, __VERSION__, __DATE__, __TIME__ );
 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
/* заглушки */
 int aktool_icode( int argc, tchar *argv[] ) { return EXIT_FAILURE; }
 int aktool_encrypt( int argc, tchar *argv[], encrypt_t work ) { return EXIT_FAILURE; }

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       akrypt.c  */
/* ----------------------------------------------------------------------------------------------- */
