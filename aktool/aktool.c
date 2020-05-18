/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл akrypt.c                                                                                  */
/*  - содержит реализацию консольной утилиты, иллюстрирующей возможности библиотеки libakrypt      */
/* ----------------------------------------------------------------------------------------------- */
 #include <time.h>
 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
 #include <aktool.h>
#ifdef _MSC_VER
 #include <strsafe.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 char audit_filename[1024];
/* функция, реализующая аудит */
 ak_function_log *audit =
#ifdef _WIN32
 aktool_audit_function;
#else
 ak_function_log_syslog;
#endif

/* ----------------------------------------------------------------------------------------------- */
 int main( int argc, TCHAR *argv[] )
{
 /* определение переменных, используемых ддя указания времени старта программы */
 #ifdef _WIN32
  time_t ptime;
  TCHAR homepath[FILENAME_MAX]
   #ifdef _MSC_VER
     , buffer[64]
   #endif
   ;
 #endif
 /* попытка русификации программы для unix-like операционных систем */
 #ifdef LIBAKRYPT_HAVE_LIBINTL_H
 /* обрабатываем настройки локали
    при инсталляции файл aktool.mo должен помещаться в /usr/share/locale/ru/LC_MESSAGES */
  #ifdef LIBAKRYPT_HAVE_LOCALE_H
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
    ak_snprintf( audit_filename, FILENAME_MAX, "%s\\.config\\libakrypt\\aktool.log", homepath );
    remove( audit_filename );
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
  if( aktool_check_command( "i", argv[1] )) return aktool_icode( argc, argv );
  if( aktool_check_command( "icode", argv[1] )) return aktool_icode( argc, argv );
  if( aktool_check_command( "a", argv[1] )) return aktool_asn1( argc, argv );
  if( aktool_check_command( "asn1parse", argv[1] )) return aktool_asn1( argc, argv );
  if( aktool_check_command( "k", argv[1] )) return aktool_key( argc, argv );
  if( aktool_check_command( "key", argv[1] )) return aktool_key( argc, argv );

 /* ничего не подошло, выводим сообщение об ошибке */
  ak_log_set_function( ak_function_log_stderr );
  ak_error_message_fmt( ak_error_undefined_function,
                                                 __func__, _("undefined command \"%s\""), argv[1] );
 return EXIT_FAILURE;
}

/* ----------------------------------------------------------------------------------------------- */
/*                         реализация функций обработки команд пользователя                        */
/* ----------------------------------------------------------------------------------------------- */
 bool_t aktool_check_command( const char *comm, TCHAR *argv )
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
  FILE *fp = fopen( audit_filename, "a+" );
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
 void aktool_set_audit( TCHAR *message )
{
  if( ak_ptr_is_equal( "stderr", message, 6 )) {
       audit = ak_function_log_stderr; /* если задан stderr, то используем готовую функцию */
  } else {
            if( strlen( message ) > 0 ) {
              memset( audit_filename, 0, 1024 );
              strncpy( audit_filename, message, 1022 );
              audit = aktool_audit_function;
            }
         }
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_file_or_directory( const TCHAR *filename )
{
 struct stat st;

  if( stat( filename, &st )) return 0;
  if( S_ISREG( st.st_mode )) return DT_REG;
  if( S_ISDIR( st.st_mode )) return DT_DIR;

 return 0;
}

/* ----------------------------------------------------------------------------------------------- */
/* выполнение однотипной процедуры с группой файлов */
 int aktool_find( const char *root , const char *mask,
                                          ak_function_find *function, ak_pointer ptr, bool_t tree )
{
  int error = ak_error_ok;

#ifdef _WIN32
  WIN32_FIND_DATA ffd;
  TCHAR szDir[MAX_PATH];
  char filename[MAX_PATH];
  HANDLE hFind = INVALID_HANDLE_VALUE;
  size_t rlen = 0, mlen = 0;

 #ifdef _MSC_VER
  if( FAILED( StringCchLength( root, MAX_PATH-1, &rlen )))
    return ak_error_message_fmt( ak_error_wrong_length, __func__ ,
                                                             "incorrect length for root variable" );
  if( FAILED( StringCchLength( mask, MAX_PATH-1, &mlen )))
    return ak_error_message_fmt( ak_error_wrong_length, __func__ ,
                                                            "incorrect length for mask variable" );
 #else
  rlen = strlen( root ); mlen = strlen( mask );
 #endif

  if( rlen > (MAX_PATH - ( mlen + 2 )))
    return ak_error_message_fmt( ak_error_wrong_length, __func__ , "directory path too long" );

 #ifdef _MSC_VER
  if( FAILED( StringCchCopy( szDir, MAX_PATH-1, root )))
    return ak_error_message_fmt( ak_error_wrong_length, __func__ ,
                                                            "incorrect copying of root variable" );
  if( FAILED( StringCchCat( szDir, MAX_PATH-1, TEXT( "\\" ))))
    return ak_error_message_fmt( ak_error_wrong_length, __func__ ,
                                                      "incorrect copying of directory separator" );
  if( FAILED( StringCchCat( szDir, MAX_PATH-1, mask )))
    return ak_error_message_fmt( ak_error_wrong_length, __func__ ,
                                                            "incorrect copying of mask variable" );
 #else
  ak_snprintf( szDir, MAX_PATH-1, "%s\\%s", root, mask );
 #endif

 /* начинаем поиск */
  if(( hFind = FindFirstFile( szDir, &ffd )) == INVALID_HANDLE_VALUE )
    return ak_error_message_fmt( ak_error_access_file, __func__ , "given mask search error" );

  do {
       if( ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ) {

         if( !strcmp( ffd.cFileName, "." )) continue;  // пропускаем себя и каталог верхнего уровня
         if( !strcmp( ffd.cFileName, ".." )) continue;

         if( tree ) { // выполняем рекурсию для вложенных каталогов
           memset( szDir, 0, MAX_PATH );
          #ifdef _MSC_VER
           if( FAILED( StringCchCopy( szDir, MAX_PATH-1, root )))
             return ak_error_message_fmt( ak_error_wrong_length, __func__ ,
                                                            "incorrect copying of root variable" );
           if( FAILED( StringCchCat( szDir, MAX_PATH-1, TEXT( "\\" ))))
             return ak_error_message_fmt( ak_error_wrong_length, __func__ ,
                                                      "incorrect copying of directory separator" );
           if( FAILED( StringCchCat( szDir, MAX_PATH-1,  ffd.cFileName )))
             return ak_error_message_fmt( ak_error_wrong_length, __func__ ,
                                                                "incorrect copying of file name" );
          #else
           ak_snprintf( szDir, MAX_PATH-1, "%s\\%s", root,  ffd.cFileName );
          #endif

           if(( error = aktool_find( szDir, mask, function, ptr, tree )) != ak_error_ok )
             ak_error_message_fmt( error,
                                         __func__, "access to \"%s\" directory denied", filename );
         }
       } else {
               if( ffd.dwFileAttributes &FILE_ATTRIBUTE_SYSTEM ) continue;
                 memset( filename, 0, FILENAME_MAX );
                #ifdef _MSC_VER
                 if( FAILED( StringCchCopy( filename, MAX_PATH-1, root )))
                   return ak_error_message_fmt( ak_error_wrong_length, __func__ ,
                                                            "incorrect copying of root variable" );
                 if( FAILED( StringCchCat( filename, MAX_PATH-1, TEXT( "\\" ))))
                   return ak_error_message_fmt( ak_error_wrong_length, __func__ ,
                                                      "incorrect copying of directory separator" );
                 if( FAILED( StringCchCat( filename, MAX_PATH-1,  ffd.cFileName )))
                   return ak_error_message_fmt( ak_error_wrong_length, __func__ ,
                                                               "incorrect copying of file namme" );
                #else
                 ak_snprintf( filename, MAX_PATH-1, "%s\\%s", root,  ffd.cFileName );
                #endif
                 function( filename, ptr );
              }

  } while( FindNextFile( hFind, &ffd ) != 0);
  FindClose(hFind);

// далее используем механизм функций open/readdir + fnmatch
#else
  DIR *dp = NULL;
  struct dirent *ent = NULL;
  char filename[FILENAME_MAX];

 /* открываем каталог */
  errno = 0;
  if(( dp = opendir( root )) == NULL ) {
    if( errno == EACCES ) return ak_error_message_fmt( ak_error_access_file,
                                          __func__ , _("access to \"%s\" directory denied"), root );
    if( errno > -1 ) return ak_error_message_fmt( ak_error_open_file,
                                                                __func__ , "%s", strerror( errno ));
  }

 /* перебираем все файлы и каталоги */
  while(( ent = readdir( dp )) != NULL ) {
    if( ent->d_type == DT_DIR ) {
      if( !strcmp( ent->d_name, "." )) continue;  // пропускаем себя и каталог верхнего уровня
      if( !strcmp( ent->d_name, ".." )) continue;

      if( tree ) { // выполняем рекурсию для вложенных каталогов
        memset( filename, 0, FILENAME_MAX );
        ak_snprintf( filename, FILENAME_MAX, "%s/%s", root, ent->d_name );
        if(( error = aktool_find( filename, mask, function, ptr, tree )) != ak_error_ok )
          ak_error_message_fmt( error, __func__, _("access to \"%s\" directory denied"), filename );
      }
    } else
       if( ent->d_type == DT_REG ) { // обрабатываем только обычные файлы
          if( !fnmatch( mask, ent->d_name, FNM_PATHNAME )) {
            memset( filename, 0, FILENAME_MAX );
            ak_snprintf( filename, FILENAME_MAX, "%s/%s", root, ent->d_name );
            function( filename, ptr );
          }
       }
  }
  if( closedir( dp )) return ak_error_message_fmt( ak_error_close_file,
                                                                __func__ , "%s", strerror( errno ));
#endif
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_file_read_by_lines( const char *filename, ak_file_read_function *function , ak_pointer ptr )
{
  #define buffer_length ( FILENAME_MAX + 160 )

  char ch;
  struct stat st;
  size_t idx = 0, off = 0;
  int fd = 0, error = ak_error_ok;
  char localbuffer[buffer_length];

 /* проверяем наличие файла и прав доступа к нему */
  if(( fd = open( filename, O_RDONLY | O_BINARY )) < 0 )
    return ak_error_message_fmt( ak_error_open_file,
                             __func__, "wrong open file \"%s\" - %s", filename, strerror( errno ));
  if( fstat( fd, &st ) ) {
    close( fd );
    return ak_error_message_fmt( ak_error_access_file, __func__ ,
                              "wrong stat file \"%s\" with error %s", filename, strerror( errno ));
  }

 /* нарезаем входные на строки длиной не более чем buffer_length - 2 символа */
  memset( localbuffer, 0, buffer_length );
  for( idx = 0; idx < (size_t) st.st_size; idx++ ) {
     if( read( fd, &ch, 1 ) != 1 ) {
       close(fd);
       return ak_error_message_fmt( ak_error_read_data, __func__ ,
                                                                "unexpected end of %s", filename );
     }
     if( off > buffer_length - 2 ) {
       close( fd );
       return ak_error_message_fmt( ak_error_read_data, __func__ ,
                          "%s has a line with more than %d symbols", filename, buffer_length - 2 );
     }
    if( ch == '\n' ) {
      #ifdef _WIN32
       if( off ) localbuffer[off-1] = 0;  /* удаляем второй символ перехода на новую строку */
      #endif
      error = function( localbuffer, ptr );
     /* далее мы очищаем строку независимо от ее содержимого */
      off = 0;
      memset( localbuffer, 0, buffer_length );
    } else localbuffer[off++] = ch;
   /* выходим из цикла если процедура проверки нарушена */
    if( error != ak_error_ok ) return error;
  }

  close( fd );
 return error;
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

 if( result >= 0 ) printf( "%serror%s: %s\n",
             ak_libakrypt_get_start_error_string(), ak_libakrypt_get_end_error_string(), string );
}

/* ----------------------------------------------------------------------------------------------- */
/*                                 реализация вывода справки                                       */
/* ----------------------------------------------------------------------------------------------- */
 int aktool_litehelp( void )
{
  printf(_("aktool (crypto application based on libakrypt library, version: %s)\n\n"),
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
  printf(_("\ncommon aktool options:\n"));
  printf(_("     --audit <file>      set the output file for errors and libakrypt audit system messages\n" ));
  printf(_("     --dont-use-colors   do not use the highlighting of output data\n"));
  printf(_("     --help              show this information\n\n"));

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int aktool_help( void )
{
  printf(_("aktool (crypto application based on libakrypt library, version: %s)\n"),
                                                                          ak_libakrypt_version( ));
  printf(_("usage \"aktool command [options] [files]\"\n\n"));
  printf(_("available commands (in short and long forms):\n"));
  printf(_("  a, asn1parse - decode and print the ASN.1 data\n"));
  printf(_("  i, icode     - calculate or check integrity codes\n"));
  printf(_("  k, key       - key generation and management functions\n"));
  printf(_("     show      - show useful information\n\n"));
  printf(_("also try:\n"));
  printf(_("  \"aktool command --help\" to get information about command options\n"));
  printf(_("  \"man aktool\" to get more information about akrypt programm and some examples\n\n"));
  printf(_("aktool compiled by %s, version: %s (%s at %s)\n"),
                                         LIBAKRYPT_COMPILER_NAME, __VERSION__, __DATE__, __TIME__ );
 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       akrypt.c  */
/* ----------------------------------------------------------------------------------------------- */
