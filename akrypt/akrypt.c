/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2014 - 2017 by Axel Kenzo, axelkenzo@mail.ru                                    */
/*   All rights reserved.                                                                          */
/*                                                                                                 */
/*  Разрешается повторное распространение и использование как в виде исходного кода, так и         */
/*  в двоичной форме, с изменениями или без, при соблюдении следующих условий:                     */
/*                                                                                                 */
/*   1. При повторном распространении исходного кода должно оставаться указанное выше уведомление  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий.                   */
/*   2. При повторном распространении двоичного кода должна сохраняться указанная выше информация  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий в документации     */
/*      и/или в других материалах, поставляемых при распространении.                               */
/*   3. Ни имя владельца авторских прав, ни имена его соратников не могут быть использованы в      */
/*      качестве рекламы или средства продвижения продуктов, основанных на этом ПО без             */
/*      предварительного письменного разрешения.                                                   */
/*                                                                                                 */
/*  ЭТА ПРОГРАММА ПРЕДОСТАВЛЕНА ВЛАДЕЛЬЦАМИ АВТОРСКИХ ПРАВ И/ИЛИ ДРУГИМИ СТОРОНАМИ "КАК ОНА ЕСТЬ"  */
/*  БЕЗ КАКОГО-ЛИБО ВИДА ГАРАНТИЙ, ВЫРАЖЕННЫХ ЯВНО ИЛИ ПОДРАЗУМЕВАЕМЫХ, ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ИМИ, ПОДРАЗУМЕВАЕМЫЕ ГАРАНТИИ КОММЕРЧЕСКОЙ ЦЕННОСТИ И ПРИГОДНОСТИ ДЛЯ КОНКРЕТНОЙ */
/*  ЦЕЛИ. НИ В КОЕМ СЛУЧАЕ НИ ОДИН ВЛАДЕЛЕЦ АВТОРСКИХ ПРАВ И НИ ОДНО ДРУГОЕ ЛИЦО, КОТОРОЕ МОЖЕТ    */
/*  ИЗМЕНЯТЬ И/ИЛИ ПОВТОРНО РАСПРОСТРАНЯТЬ ПРОГРАММУ, КАК БЫЛО СКАЗАНО ВЫШЕ, НЕ НЕСЁТ              */
/*  ОТВЕТСТВЕННОСТИ, ВКЛЮЧАЯ ЛЮБЫЕ ОБЩИЕ, СЛУЧАЙНЫЕ, СПЕЦИАЛЬНЫЕ ИЛИ ПОСЛЕДОВАВШИЕ УБЫТКИ,         */
/*  ВСЛЕДСТВИЕ ИСПОЛЬЗОВАНИЯ ИЛИ НЕВОЗМОЖНОСТИ ИСПОЛЬЗОВАНИЯ ПРОГРАММЫ (ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ПОТЕРЕЙ ДАННЫХ, ИЛИ ДАННЫМИ, СТАВШИМИ НЕПРАВИЛЬНЫМИ, ИЛИ ПОТЕРЯМИ ПРИНЕСЕННЫМИ   */
/*  ИЗ-ЗА ВАС ИЛИ ТРЕТЬИХ ЛИЦ, ИЛИ ОТКАЗОМ ПРОГРАММЫ РАБОТАТЬ СОВМЕСТНО С ДРУГИМИ ПРОГРАММАМИ),    */
/*  ДАЖЕ ЕСЛИ ТАКОЙ ВЛАДЕЛЕЦ ИЛИ ДРУГОЕ ЛИЦО БЫЛИ ИЗВЕЩЕНЫ О ВОЗМОЖНОСТИ ТАКИХ УБЫТКОВ.            */
/*                                                                                                 */
/*   akrypt.c                                                                                      */
/* ----------------------------------------------------------------------------------------------- */
 #include <akrypt.h>

/* ----------------------------------------------------------------------------------------------- */
/* имя пользовательского файла для вывода аудита */
 char audit_filename[1024];
 ak_function_log *audit = NULL;

/* ----------------------------------------------------------------------------------------------- */
 int main( int argc, char *argv[] )
{
 /* проверяем, что пользователем должна быть задана команда */
  if( argc < 2 ) return akrypt_litehelp();

 /* проверяем флаги вывода справочной информации */
  if( akrypt_check_command( "-h", argv[1] )) return akrypt_help();
  if( akrypt_check_command( "--help", argv[1] )) return akrypt_help();
  if( akrypt_check_command( "/?", argv[1] )) return akrypt_help();

 /* выполняем команду пользователя */
  if( akrypt_check_command( "show", argv[1] )) return akrypt_show( argc, argv );
  if( akrypt_check_command( "hash", argv[1] )) return akrypt_hash( argc, argv );

 /* ничего не подошло, выводим сообщение об ошибке */
  ak_log_set_function( ak_function_log_stderr );
  ak_error_message_fmt( ak_error_undefined_function, __func__, "unknown command \"%s\"", argv[1] );

 return EXIT_FAILURE;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_bool akrypt_check_command( const char *comm, char *argv )
{
 size_t len = strlen( comm );

  if( strlen( argv ) != len ) return ak_false;
  if( strncmp( comm, argv, len )) return ak_false;
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/* вывод сообщений в заданный пользователем файл, а также в стандартный демон вывода сообщений */
 int akrypt_audit_function( const char *message )
{
  FILE *fp = fopen( audit_filename, "a+" );
   /* функция выводит сообщения в заданный файл */
    if( !fp ) return ak_error_open_file;
    fprintf( fp, "%s\n", message );
#ifdef __linux__
    ak_function_log_syslog( message );
#endif
    if( fclose(fp) == EOF ) return ak_error_access_file;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/* установка функции вывода сообщений о ходе выполнения программы */
 void akrypt_set_audit( const char *message )
{
  if( ak_ptr_is_equal( "stderr", (void *) message, 6 ))
       audit = ak_function_log_stderr;
       /* если задан stderr, то используем готовую функцию */
      else {
            memset( audit_filename, 0, 1024 );
            strncpy( audit_filename, message, 1022 );
            audit = akrypt_audit_function;
           }
}


/* ----------------------------------------------------------------------------------------------- */
/* выполнение однотипной процедуры с группой файлов */
 int akrypt_find( const char *root , const char *mask,
                                ak_function_find_handle *function, ak_handle handle, ak_bool tree )
{
#ifdef _WIN32
  _finddata_t fd;
  long dsp = _findfirst(( root + ak_file_separator() + mask ).c_str(), &fd );

  // поиск файлов
  if( dsp != -1) do{
       #ifdef _MSC_VER
         /*
           if( fd.attrib ==  6 ) { f( root.c_str(), fd.name ); continue; }
           if( fd.attrib == 32 ) { f( root.c_str(), fd.name ); continue; }
           if( fd.attrib == 34 ) { f( root.c_str(), fd.name ); continue; }
         */
         if ((fd.attrib & 0x10) == 0) { f( root.c_str(), fd.name ); continue; }
       #else
          if( fd.attrib != _A_SUBDIR ) f( root.c_str(), fd.name );
       #endif
    } while( _findnext( dsp, &fd ) != -1 );
  _findclose( dsp );

  // поиск в подкаталогах
  if( do_tree ) {
    dsp = _findfirst(( root + ak_file_separator() + "*" ).c_str(), &fd );
    if( dsp != -1) do {
        #ifdef _MSC_VER
          bool inflag = false; // такая петрушка из-за того, что файл io.h
           if( fd.attrib == 16 ) inflag = true; // не содержит необходимых констант
           if( fd.attrib == 17 ) inflag = true;
           if( fd.attrib == 18 ) inflag = true;
           if( fd.attrib == 19 ) inflag = true;
           if( fd.attrib == 8214 ) inflag = true;
           if( inflag ) {
        #else
          if( fd.attrib == _A_SUBDIR ) {
        #endif
          if( !strcmp( fd.name, "." )) continue;  // отбрасываем лишнее
          if( !strcmp( fd.name, ".." )) continue;
          ak_foreach_file( root + ak_file_separator() + fd.name,
                                                          mask, f, do_tree );
        }
      } while( _findnext( dsp, &fd ) != -1 );
    _findclose( dsp );
  }

// далее используем механизм функций open/readdir + fnmatch
#else
  DIR *dp = NULL;
  struct dirent *ent = NULL;
  char filename[FILENAME_MAX];

 /* открытваем каталог */
  errno = 0;
  if(( dp = opendir( root )) == NULL ) {
    if( errno == EACCES ) return ak_error_message_fmt( ak_error_access_file,
                                             __func__ , "access to \"%s\" directory denied", root );
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
        akrypt_find( filename, mask, function, handle, tree );
      }
    } else
       if( ent->d_type == DT_REG ) { // обрабатываем только обычные файлы
          if( !fnmatch( mask, ent->d_name, FNM_PATHNAME )) {
            memset( filename, 0, FILENAME_MAX );
            ak_snprintf( filename, FILENAME_MAX, "%s/%s", root, ent->d_name );
            function( handle, filename );
          }
       }
  }
  if( closedir( dp )) return ak_error_message_fmt( ak_error_close_file,
                                                                __func__ , "%s", strerror( errno ));
#endif
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_file_or_directory( const char *filename )
{
 struct stat st;

  if( stat( filename, &st )) return 0;
  if( S_ISREG( st.st_mode )) return DT_REG;
  if( S_ISDIR( st.st_mode )) return DT_DIR;

 return 0;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                 реализация вывода справки                                       */
/* ----------------------------------------------------------------------------------------------- */
 int akrypt_litehelp( void )
{
  printf("akrypt (crypto application based on libakrypt library, version: %s)\n",
                                                                         ak_libakrypt_version( ));
  printf("try \"akrypt --help\" to get more information\n");
 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 int akrypt_help( void )
{
  printf("akrypt (crypto application based on libakrypt library, version: %s)\n",
                                                                         ak_libakrypt_version( ));
  printf("usage \"akrypt command [options] [files]\"\n\n");
  printf("available commands:\n");
  printf("  hash    calculation and checking control sums\n");
  printf("  show    show useful information\n\n");
  printf("try \"akrypt command --help\" to get information about command options\n");
  printf("try \"man akrypt\" to get more information about akrypt programm and some examples\n");

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       akrypt.c  */
/* ----------------------------------------------------------------------------------------------- */
