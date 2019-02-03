/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_tools.с                                                                                */
/*  - содержит реализацию служебных функций, не экспортируемых за пределы библиотеки               */
/* ----------------------------------------------------------------------------------------------- */

/* ----------------------------------------------------------------------------------------------- */
/* это объявление нужно для использования функции fdopen() */
#ifdef __linux__
 #ifndef _POSIX_C_SOURCE
   #define _POSIX_C_SOURCE 2
 #endif
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_STDIO_H
 #include <stdio.h>
#else
 #error Library cannot be compiled without stdio.h header
#endif
#ifdef LIBAKRYPT_HAVE_STDLIB_H
 #include <stdlib.h>
#else
 #error Library cannot be compiled without stdlib.h header
#endif
#ifdef LIBAKRYPT_HAVE_STRING_H
 #include <string.h>
#else
 #error Library cannot be compiled without string.h header
#endif
#ifdef LIBAKRYPT_HAVE_ERRNO_H
 #include <errno.h>
#else
 #error Library cannot be compiled without errno.h header
#endif
#ifdef LIBAKRYPT_HAVE_STDARG_H
 #include <stdarg.h>
#else
 #error Library cannot be compiled without stdarg.h header
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_FCNTL_H
 #include <fcntl.h>
#endif
#ifdef LIBAKRYPT_HAVE_SYSSTAT_H
 #include <sys/stat.h>
#endif
#ifdef LIBAKRYPT_HAVE_TERMIOS_H
 #include <termios.h>
#endif
#ifdef LIBAKRYPT_HAVE_UNISTD_H
 #include <unistd.h>
#endif
#ifdef LIBAKRYPT_HAVE_SYSLOG_H
 #include <syslog.h>
#endif
#ifdef LIBAKRYPT_HAVE_UNISTD_H
 #include <unistd.h>
#endif
#ifdef LIBAKRYPT_HAVE_LIMITS_H
 #include <limits.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_PTHREAD
 #include <pthread.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef _MSC_VER
 #include <share.h>
 #include <direct.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_tools.h>

/* ----------------------------------------------------------------------------------------------- */
/*!  Переменная, содержащая в себе код последней ошибки                                            */
 static int ak_errno = ak_error_ok;

/* ----------------------------------------------------------------------------------------------- */
/*! Внутренний указатель на функцию аудита                                                         */
 static ak_function_log *ak_function_log_default = NULL;
#ifdef LIBAKRYPT_HAVE_PTHREAD
 static pthread_mutex_t ak_function_log_default_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тип данных для хранения одной опции библиотеки */
 typedef struct option {
  /*! \brief Человекочитаемое имя опции, используется для поиска и установки значения */
   const char *name;
  /*! \brief Численное значение опции (31 значащий бит + знак) */
   ak_int64 value;
 } *ak_option;

/* ----------------------------------------------------------------------------------------------- */
/*! Константные значения опций (значения по-умолчанию) */
 static struct option options[] = {
     { "log_level", ak_log_standard },
     { "context_manager_size", 32 },
     { "context_manager_max_size", 4096 },
     { "key_number_length", 16 },
     { "pbkdf2_iteration_count", 2000 },
     { "hmac_key_count_resource", 65536 },

  /* значение константы задает максимальный объем зашифрованной информации на одном ключе в 4 Mб:
                                 524288 блока x 8 байт на блок = 4.194.304 байт = 4096 Кб = 4 Mб   */
     { "magma_cipher_resource", 524288 },

  /* значение константы задает максимальный объем зашифрованной информации на одном ключе в 32 Mб:
                             2097152 блока x 16 байт на блок = 33.554.432 байт = 32768 Кб = 32 Mб  */
     { "kuznechik_cipher_resource", 2097152 },

     { NULL, 0 } /* завершающая константа, должна всегда принимать нулевые значения */
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \b Внимание. Функция экспортируется.

    \return Общее количество опций библиотеки.                                                     */
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_libakrypt_options_count( void )
{
  return ( sizeof( options )/( sizeof( struct option ))-1 );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param name Имя опции
    \return Значение опции с заданным именем. Если имя указано неверно, то возвращается
    ошибка \ref ak_error_wrong_option.                                                             */
/* ----------------------------------------------------------------------------------------------- */
 ak_int64 ak_libakrypt_get_option( const char *name )
{
  size_t i = 0;
  ak_int64 result = ak_error_wrong_option;
  for( i = 0; i < ak_libakrypt_options_count(); i++ ) {
     if( strncmp( name, options[i].name, strlen( options[i].name )) == 0 ) result = options[i].value;
  }
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \b Внимание! Функция не проверяет и не интерпретирует значение устанавливааемой опции.

    \param name Имя опции
    \param value Значение опции

    \return В случае удачного установления значения опции возввращается \ref ak_error_ok.
     Если имя опции указано неверно, то возвращается ошибка \ref ak_error_wrong_option.            */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_set_option( const char *name, const ak_int64 value )
{
  size_t i = 0;
  int result = ak_error_wrong_option;
  for( i = 0; i < ak_libakrypt_options_count(); i++ ) {
     if( strncmp( name, options[i].name, strlen( options[i].name )) == 0 ) {
       options[i].value = value;
       result = ak_error_ok;
     }
  }
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция возвращает указатель на строку символов, содержащую человекочитаемое имя опции
    библиотеки. Для строки выделяется память, которая должна быть позднее удалена пользователем
    самостоятельно.

    \b Внимание. Функция экспортируется.

    \param index Индекс опции, должен быть от нуля до значения,
    возвращаемого функцией ak_libakrypt_options_count().

    \return Строка симовлов, содержащая имя функции, в случае правильно определенного индекса.
    В противном случае, возвращается NULL.                                                         */
/* ----------------------------------------------------------------------------------------------- */
 char *ak_libakrypt_get_option_name( const size_t index )
{
 size_t len = 0;
 char *ptr = NULL;
 if( index >= ak_libakrypt_options_count() ) return ak_null_string;
  else {
    len = strlen( options[index].name ) + 1;
    if(( ptr = malloc( len )) == NULL ) {
      ak_error_message( ak_error_null_pointer, __func__, "incorrect memory allocation");
    } else memcpy( ptr, options[index].name, len );
  }
  return ptr;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \b Внимание. Функция экспортируется.

    \param index Индекс опции, должен быть от нуля до значения,
    возвращаемого функцией ak_libakrypt_options_count().

    \return Целое неотрицательное число, содержащее значение опции с заданным индексом.
    В случае неправильно определенного индекса возвращается значение \ref ak_error_wrong_option.   */
/* ----------------------------------------------------------------------------------------------- */
 ak_int64 ak_libakrypt_get_option_value( const size_t index )
{
 if( index >= ak_libakrypt_options_count() ) return ak_error_wrong_option;
  else return options[index].value;
}


/* ----------------------------------------------------------------------------------------------- */
/*! @param hpath Буффер в который будет помещено имя домашнего каталога пользователя.
    @param size Размер буффера в байтах.

    @return В случае возникновения ошибки возвращается ее код. В случае успеха
    возвращается \ref ak_error_ok.                                                                 */
/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_get_home_path( char *hpath, const size_t size )
{
 if( hpath == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                         "using null pointer to filename buffer" );
 if( !size ) return ak_error_message( ak_error_zero_length, __func__,
                                                               "using a buffer with zero length" );
 memset( hpath, 0, size );

 #ifdef _WIN32
  /* в начале определяем, находимся ли мы в консоли MSys */
   GetEnvironmentVariableA( "HOME", hpath, size );
  /* если мы находимся не в консоли, то строка hpath должна быть пустой */
   if( strlen( hpath ) == 0 ) {
     GetEnvironmentVariableA( "USERPROFILE", hpath, size );
   }
 #else
   ak_snprintf( hpath, size, "%s", getenv( "HOME" ));
 #endif

 if( strlen( hpath ) == 0 ) return ak_error_message( ak_error_undefined_value, __func__,
                                                                           "wrong user home path");
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция создает имя файла в котором содержатся настройки библиотеки.

   @param filename Массив, куда помещается имя файла. Память под массив
          должна быть быделена заранее.
   @param size Размер выделенной памяти.
   @param where Указатель на то, в каком каталоге будет расположен файл с настройками.
          Значение 0 - домашний каталог, значение 1 - общесистемный каталог
   @return Функция возвращает код ошибки.                                                          */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_libakrypt_create_filename_for_options( char *filename,
                                                             const size_t size, const int where  )
{
 int error = ak_error_ok;
 char hpath[FILENAME_MAX];

  memset( (void *)filename, 0, size );
  memset( (void *)hpath, 0, FILENAME_MAX );

  switch( where )
 {
   case 0  : /* имя файла помещается в домашний каталог пользователя */
             if(( error = ak_libakrypt_get_home_path( hpath, FILENAME_MAX )) != ak_error_ok )
                 return ak_error_message( error, __func__, "wrong libakrypt.conf name creation" );
             #ifdef _WIN32
              ak_snprintf( filename, size, "%s\\.config\\libakrypt\\libakrypt.conf", hpath );
             #else
              ak_snprintf( filename, size, "%s/.config/libakrypt/libakrypt.conf", hpath );
             #endif
             break;

   case 1  : { /* имя файла помещается в общесистемный каталог */
               size_t len = 0;
               if(( len = strlen( LIBAKRYPT_OPTIONS_PATH )) > FILENAME_MAX-16 ) {
                 return ak_error_message( ak_error_wrong_length, __func__ ,
                                                           "wrong length of predefined filepath" );
               }
               memcpy( hpath, LIBAKRYPT_OPTIONS_PATH, len );
             }
             #ifdef _WIN32
              ak_snprintf( filename, size, "%s\\libakrypt.conf", hpath );
             #else
              ak_snprintf( filename, size, "%s/libakrypt.conf", hpath );
             #endif
             break;
   default : return ak_error_message( ak_error_undefined_value, __func__,
                                                       "unexpected value of \"where\" parameter ");
 }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static ak_bool ak_libakrypt_load_one_option( const char *string, const char *field, ak_int64 *value )
{
  char *ptr = NULL, *endptr = NULL;
  if(( ptr = strstr( string, field )) != NULL ) {
    ak_int64 val = ( ak_int64 ) strtoll( ptr += strlen(field), &endptr, 10 ); // strtoll
    if(( endptr != NULL ) && ( ptr == endptr )) {
      ak_error_message_fmt( ak_error_undefined_value, __func__,
                                    "using an undefinded value for variable %s", field );
      return ak_false;
    }
    if(( errno == ERANGE && ( val >= INT_MAX || val <= INT_MIN )) || (errno != 0 && val == 0)) {
      ak_error_message_fmt( ak_error_undefined_value, __func__,
                                                     "%s for field %s", strerror( errno ), field );
    } else {
             *value = val;
             return ak_true;
           }
  }
 return ak_false;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция считывает опции из открытого файла, дескриптор которого передается в
    качестве аргумента функции.

    @param fd Дескриптор файла. Должен быть предварительно открыт на чтение с помощью функции
    ak_file_is_exist().

    @return Функция возвращает код ошибки или \ref ak_error_ok.                                    */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_libakrypt_load_options_from_file( ak_file fd )
{
 int off = 0;
 size_t idx = 0;
 char ch, localbuffer[1024];

 /* нарезаем входные на строки длиной не более чем 1022 символа */
  memset( localbuffer, 0, 1024 );
  for( idx = 0; idx < (size_t) fd->size; idx++ ) {
     if( fread( &ch, 1, 1, fd->fp ) != 1 ) {
       ak_file_close(fd);
       return ak_error_message( ak_error_read_data, __func__ ,
                                                         "unexpected end of libakrypt.conf file" );
     }
     if( off > 1022 ) {
       ak_file_close( fd );
       return ak_error_message( ak_error_read_data, __func__ ,
                                         "libakrypt.conf has a line with more than 1022 symbols" );
     }
    if( ch == '\n' ) {
      if((strlen(localbuffer) != 0 ) && ( strchr( localbuffer, '#' ) == 0 )) {
        ak_int64 value = 0;

        /* устанавливаем уровень аудита */
        if( ak_libakrypt_load_one_option( localbuffer, "log_level = ", &value ))
          ak_libakrypt_set_option( "log_level", value );

        /* устанавливаем минимальный размер структуры управления контекстами */
        if( ak_libakrypt_load_one_option( localbuffer, "context_manager_size = ", &value )) {
          if( value < 32 ) value = 32;
          if( value > 65536 ) value = 65536;
          ak_libakrypt_set_option( "context_manager_size", value );
        }

       /* устанавливаем максимально возможный размер структуры управления контекстами */
        if( ak_libakrypt_load_one_option( localbuffer, "context_manager_max_size = ", &value )) {
          if( value < 4096 ) value = 4096;
          if( value > 2147483647 ) value = 2147483647;
          ak_libakrypt_set_option( "context_manager_max_size", value );
        }

       /* устанавливаем длину номера ключа */
        if( ak_libakrypt_load_one_option( localbuffer, "key_number_length = ", &value )) {
          if( value < 16 ) value = 16;
          if( value > 32 ) value = 32;
          ak_libakrypt_set_option( "key_number_length", value );
        }

       /* устанавливаем количество циклов в алгоритме pbkdf2 */
        if( ak_libakrypt_load_one_option( localbuffer, "pbkdf2_iteration_count = ", &value )) {
          if( value < 1000 ) value = 1000;
          if( value > 32768 ) value = 32768;
          ak_libakrypt_set_option( "pbkdf2_iteration_count", value );
        }

       /* устанавливаем ресурс ключа выработки имитовставки для алгоритма HMAC */
        if( ak_libakrypt_load_one_option( localbuffer, "hmac_key_counter_resource = ", &value )) {
          if( value < 1024 ) value = 1024;
          if( value > 2147483647 ) value = 2147483647;
          ak_libakrypt_set_option( "hmac_key_count_resource", value );
        }

       /* устанавливаем ресурс ключа алгоритма блочного шифрования Магма */
        if( ak_libakrypt_load_one_option( localbuffer, "magma_cipher_resource = ", &value )) {
          if( value < 1024 ) value = 1024;
          if( value > 2147483647 ) value = 2147483647;
          ak_libakrypt_set_option( "magma_cipher_resource", value );
        }
       /* устанавливаем ресурс ключа алгоритма блочного шифрования Магма */
        if( ak_libakrypt_load_one_option( localbuffer, "kuznechik_cipher_resource = ", &value )) {
          if( value < 1024 ) value = 1024;
          if( value > 2147483647 ) value = 2147483647;
          ak_libakrypt_set_option( "kuznechik_cipher_resource", value );
        }

      } /* далее мы очищаем строку независимо от ее содержимого */
      off = 0;
      memset( localbuffer, 0, 1024 );
    } else localbuffer[off++] = ch;
  }

  /* закрываем */
  ak_file_close(fd);

  /* выводим сообщение об установленных параметрах библиотеки */
  if( ak_libakrypt_get_option( "log_level" ) > ak_log_standard ) {
    size_t i = 0;

    ak_error_message_fmt( ak_error_ok, __func__, "libakrypt version: %s", ak_libakrypt_version( ));
    /* далее мы пропускаем вывод информации об архитектуре,
       поскольку она будет далее тестироваться отдельно     */
    for( i = 1; i < ak_libakrypt_options_count(); i++ )
       ak_error_message_fmt( ak_error_ok, __func__,
                                   "value of option %s is %d", options[i].name, options[i].value );
  }
  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_libakrypt_write_options( void )
{
  size_t i;
  struct file fd;
  int error = ak_error_ok;
  char hpath[FILENAME_MAX], filename[FILENAME_MAX];

  memset( hpath, 0, FILENAME_MAX );
  memset( filename, 9, FILENAME_MAX );

 /* начинаем последовательно создавать подкаталоги */
  if(( error = ak_libakrypt_get_home_path( hpath, FILENAME_MAX )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong libakrypt.conf name creation" );

 /* создаем .config */
 #ifdef _WIN32
  ak_snprintf( filename, FILENAME_MAX, "%s\\.config", hpath );
  #ifdef _MSC_VER
   if( _mkdir( filename ) < 0 ) {
  #else
   if( mkdir( filename ) < 0 ) {
  #endif
 #else
  ak_snprintf( filename, FILENAME_MAX, "%s/.config", hpath );
  if( mkdir( filename, S_IRWXU ) < 0 ) {
 #endif
    if( errno != EEXIST ) {
      return ak_error_message_fmt( ak_error_access_file, __func__,
       "wrong creation of %s directory with error: %s", filename, strerror( errno ));
    }
  }

 /* создаем libakrypt */
 #ifdef _WIN32
  ak_snprintf( hpath, FILENAME_MAX, "%s\\libakrypt", filename );
  #ifdef _MSC_VER
   if( _mkdir( hpath ) < 0 ) {
  #else
   if( mkdir( hpath ) < 0 ) {
  #endif
 #else
  ak_snprintf( hpath, FILENAME_MAX, "%s/libakrypt", filename );
  if( mkdir( hpath, S_IRWXU ) < 0 ) {
 #endif
    if( errno != EEXIST ) {
      return ak_error_message_fmt( ak_error_access_file, __func__,
       "wrong creation of %s directory with error: %s", filename, strerror( errno ));
    }
  }

 /* теперь начинаем манипуляции с файлом */
 #ifdef _WIN32
  ak_snprintf( filename, FILENAME_MAX, "%s\\libakrypt.conf", hpath );
 #else
  ak_snprintf( filename, FILENAME_MAX, "%s/libakrypt.conf", hpath );
 #endif

  if(( error = ak_file_create_to_write( &fd, filename )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong creation of libakrypt.conf file");

  for( i = 0; i < ak_libakrypt_options_count(); i++ ) {
    memset( hpath, 0, ak_min( 1024, FILENAME_MAX ));
    ak_snprintf( hpath, FILENAME_MAX - 1, "%s = %d\n", options[i].name, options[i].value );
    if( fwrite( hpath, 1, strlen( hpath ), fd.fp ) < 1 ) {
      ak_error_message_fmt( error = ak_error_write_data, __func__,
                      "option %s stored with error: %s", options[i].name, strerror( errno ));
    }
  }
  ak_file_close( &fd );
  if( error == ak_error_ok )
    ak_error_message_fmt( ak_error_ok, __func__, "all options stored in %s file", filename );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция последовательно ищет файл `libakrypt.conf` сначала в домашнем каталоге пользователя,
    потом в каталоге, указанном при сборке библиотеки с помощью флага `LIBAKRYPT_CONF`. В случае,
    если ни в одном из указанных мест файл не найден, то функция создает файл `libakrypt.conf`
    в домашнем каталоге пользователя со значениями по-умолчанию.                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_libakrypt_load_options( void )
{
 struct file fd;
 int error = ak_error_ok;
 char name[FILENAME_MAX];

/* создаем имя файла, расположенного в домашнем каталоге */
 if(( error =
       ak_libakrypt_create_filename_for_options( name, FILENAME_MAX, 0 )) != ak_error_ok ) {
   ak_error_message( error, __func__, "incorrect name generation for options file");
   return ak_false;
 }
/* пытаемся считать данные из указанного файла */
 if( ak_file_open_to_read( &fd, name ) == ak_error_ok ) {
   if(( error = ak_libakrypt_load_options_from_file( &fd )) == ak_error_ok ) {
     if( ak_libakrypt_get_option( "log_level" ) > ak_log_standard ) {
       ak_error_message_fmt( ak_error_ok, __func__,
                                                 "all options was read from %s file", name );
     }
     return ak_true;
   } else {
       ak_error_message_fmt( error, __func__, "wrong options reading from %s file", name );
       return ak_false;
     }
 }

/* создаем имя файла, расположенного в системном каталоге */
 if(( error =
       ak_libakrypt_create_filename_for_options( name, FILENAME_MAX, 1 )) != ak_error_ok ) {
   ak_error_message( error, __func__, "incorrect name generation for options file");
   return ak_false;
 }
/* пытаемся считать данные из указанного файла */
 if( ak_file_open_to_read( &fd, name ) == ak_error_ok ) {
   if(( error = ak_libakrypt_load_options_from_file( &fd )) == ak_error_ok ) {
     if( ak_libakrypt_get_option( "log_level" ) > ak_log_standard ) {
       ak_error_message_fmt( ak_error_ok, __func__,
                                                 "all options was read from %s file", name );
     }
     return ak_true;
   } else {
       ak_error_message_fmt( error, __func__, "wrong options reading from %s file", name );
       return ak_false;
     }
 } else ak_error_message( ak_error_access_file, __func__,
                         "file libakrypt.conf not found either in home or system directory");

 /* формируем дерево подкаталогов и записываем файл с настройками */
  if(( error = ak_libakrypt_write_options( )) != ak_error_ok ) {
    ak_error_message_fmt( error, __func__, "wrong creation a libakrypt.conf file" );
    return ak_false;
  }

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_file_open_to_read( ak_file file, const char *filename )
{
#ifdef _WIN32
  struct _stat st;
  if( _stat( filename, &st ) < 0 ) {
#else
  struct stat st;
  if( stat( filename, &st ) < 0 ) {
#endif
    switch( errno ) {
      case EACCES: return ak_error_message_fmt( ak_error_access_file, __func__,
                                 "incorrect access to file %s [%s]", filename, strerror( errno ));
      default: return ak_error_message_fmt( ak_error_open_file, __func__ ,
                                     "wrong opening a file %s [%s]", filename, strerror( errno ));
    }
  }

 /* открываем файл */
  if(( file->fp = fopen( filename, "rb" )) == NULL )
    return ak_error_message_fmt( ak_error_open_file, __func__ ,
                                     "wrong opening a file %s [%s]", filename, strerror( errno ));
 /* заполняем данные */
  file->size = ( ak_int64 )st.st_size;
 #ifdef _WIN32
  file->blksize = 4096;
 #else
  file->blksize = ( ak_int64 )st.st_blksize;
 #endif
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_file_create_to_write( ak_file file, const char *filename )
{
 #ifdef _WIN32
  if(( file->fp = fopen( filename, "wb" )) == NULL )
    return ak_error_message_fmt( ak_error_create_file, __func__,
                                   "wrong creation a file %s [%s]", filename, strerror( errno ));
 #else
  int fd = creat( filename, S_IRUSR | S_IWUSR ); /* мы устанавливаем минимальные права */
  if( fd < 0 ) return ak_error_message_fmt( ak_error_create_file, __func__,
                                   "wrong creation a file %s [%s]", filename, strerror( errno ));
  if(( file->fp = fdopen( fd, "wb" )) == NULL )
    return ak_error_message_fmt( ak_error_create_file, __func__,
                        "wrong creation a file %s via fdopen [%s]", filename, strerror( errno ));
#endif

  file->size = 0;
#ifdef _WIN32
  file->blksize = 4096;
#else
  struct stat st;
  if( fstat( fd, &st )) {
    close( fd );
    return ak_error_message_fmt( ak_error_access_file,  __func__,
                                "incorrect access to file %s [%s]", filename, strerror( errno ));
  } else file->blksize = ( ak_int64 )st.st_blksize;
#endif

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_file_close( ak_file file )
{
  if( fclose( file->fp ) != 0 ) return ak_error_message_fmt( ak_error_close_file, __func__ ,
                                                 "wrong closing a file [%s]", strerror( errno ));
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_log_get_level( void ) { return (int)ak_libakrypt_get_option("log_level"); }

/* ----------------------------------------------------------------------------------------------- */
/*! Все сообщения библиотеки могут быть разделены на три уровня.

    \li Первый уровень аудита определяется константой \ref ak_log_none. На этом уровне выводятся
    сообщения об ошибках, а также минимальный набор сообщений, включающий в себя факт
    успешного тестирования работоспособности криптографических механизмов.

    \li Второй уровень аудита определяется константой \ref ak_log_standard. На этом уровене
    выводятся все сообщения из первого уровня, а также сообщения о фактах использования
    ключевой информации.

    \li Третий (максимальный) уровень аудита определяется константой \ref ak_log_maximum.
    На этом уровне выводятся все сообщения, доступные на первых двух уровнях, а также
    сообщения отладочного характера, позхволяющие прослдедить логику работы функций библиотеки.

    \param level Уровень аудита, может принимать значения \ref ak_log_none,
    \ref ak_log_standard и \ref ak_log_maximum

    \note Допускается передавать в функцию любое целое число, не превосходящее 16.
    Однако для всех значений от \ref ak_log_maximum  до 16 поведение функции аудита
    будет одинаковым. Дополнительный лиапазон преднахначен для приложений библиотеки.

    \return Функция всегда возвращает \ref ak_error_ok (ноль).                                     */
/* ----------------------------------------------------------------------------------------------- */
 int ak_log_set_level( int level )
{
 int value = level;

   if( value < 0 ) return ak_libakrypt_set_option("log_level", ak_log_none );
   if( value > 16 ) value = 16;
 return ak_libakrypt_set_option("log_level", value );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \b Внимание. Функция экспортируется.
    \param value Код ошибки, который будет установлен. В случае, если значение value положительно,
    то код ошибки полагается равным величине \ref ak_error_ok (ноль).
    \return Функция возвращает устанавливаемое значение.                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_error_set_value( const int value )
{
  return ( ak_errno = value );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \b Внимание. Функция экспортируется.
    \return Функция возвращает текущее значение кода ошибки. Данное значение не является
    защищенным от возможности изменения различными потоками выполнения программы.                  */
/* ----------------------------------------------------------------------------------------------- */
 int ak_error_get_value( void )
{
  return ak_errno;
}

#ifdef LIBAKRYPT_HAVE_SYSLOG_H
/* ----------------------------------------------------------------------------------------------- */
/*! \b Внимание. Функция экспортируется.
    \param message Выводимое сообщение.
    \return В случае успеха, возвращается ak_error_ok (ноль). В случае возникновения ошибки,
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_function_log_syslog( const char *message )
{
 #ifdef __linux__
   int priority = LOG_AUTHPRIV | LOG_NOTICE;
 #else
   int priority = LOG_USER;
 #endif
  if( message != NULL ) syslog( priority, "%s", message );
 return ak_error_ok;
}
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \b Внимание. Функция экспортируется.
    \param message Выводимое сообщение
    \return В случае успеха, возвращается ak_error_ok (ноль). В случае возникновения ошибки,
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_function_log_stderr( const char *message )
{
  if( message != NULL ) fprintf( stderr, "%s\n", message );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция устанавливает в качестве основного обработчика
    вывода сообщений функцию, задаваемую указателем function. Если аргумент function равен NULL,
    то используется функция по-умолчанию.
    Выбор того, какая именно функция будет установлена по-умолчанию, не фискирован.
    В текущей версии библиотеки он зависит от используемой операционной системы, например,
    под ОС Linux это вывод с использованием демона syslogd.

    \b Внимание. Функция экспортируется.

    \param function Указатель на функцию вывода сообщений.
    \return Функция всегда возвращает ak_error_ok (ноль).                                          */
/* ----------------------------------------------------------------------------------------------- */
 int ak_log_set_function( ak_function_log *function )
{
#ifdef LIBAKRYPT_HAVE_PTHREAD
  pthread_mutex_lock( &ak_function_log_default_mutex );
#endif
  if( function != NULL ) ak_function_log_default = function;
   else {
    #ifdef LIBAKRYPT_HAVE_SYSLOG_H
      ak_function_log_default = ak_function_log_syslog;
    #else
      ak_function_log_default = ak_function_log_stderr;
    #endif
   }
#ifdef LIBAKRYPT_HAVE_PTHREAD
  pthread_mutex_unlock( &ak_function_log_default_mutex );
#endif
  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция использует установленную ранее функцию-обработчик сообщений. Если сообщение,
    или обработчик не определены (равны NULL) возвращается код ошибки.

    \b Внимание. Функция экспортируется.

    \param message выводимое сообщение
    \return в случае успеха, возвращается ak_error_ok (ноль). В случае возникновения ошибки,
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_log_set_message( const char *message )
{
  int result = ak_error_ok;
  if( ak_function_log_default == NULL ) return ak_error_set_value( ak_error_undefined_function );
  if( message == NULL ) {
    return ak_error_message( ak_error_null_pointer, __func__ , "using a NULL string for message" );
  } else {
          #ifdef LIBAKRYPT_HAVE_PTHREAD
           pthread_mutex_lock( &ak_function_log_default_mutex );
          #endif
           result = ak_function_log_default( message );
          #ifdef LIBAKRYPT_HAVE_PTHREAD
           pthread_mutex_unlock( &ak_function_log_default_mutex );
          #endif
      return result;
    }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param str Строка, в которую помещается результат (сообщение)
    \param size Максимальный размер помещаемого в строку str сообщения
    \param format Форматная строка, в соответствии с которой формируется сообщение

    \return Функция возвращает значение, которое вернул вызов системной (библиотечной) функции
    форматирования строки.                                                                         */
/* ----------------------------------------------------------------------------------------------- */
 int ak_snprintf( char *str, size_t size, const char *format, ... )
{
  int result = 0;
  va_list args;
  va_start( args, format );

 #ifdef _MSC_VER
  #if _MSC_VER > 1310
    result = _vsnprintf_s( str, size, size, format, args );
  #else
    result = _vsnprintf( str, size, format, args );
  #endif
 #else
  result = vsnprintf( str, size, format, args );
 #endif
  va_end( args );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция устанавливает текущее значение кода ошибки, формирует строку специального вида и
    выводит сформированную строку в логгер с помомощью функции ak_log_set_message().

    \b Внимание. Функция экспортируется.

    \param code Код ошибки
    \param message Читаемое (понятное для пользователя) сообщение
    \param function Имя функции, вызвавшей ошибку

    \return Функция возвращает установленный код ошибки.                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_error_message( const int code, const char *function, const char *message )
{
 /* здесь мы выводим в логгер строку вида [pid] function: message (code: n)                        */
  char error_event_string[1024];
  memset( error_event_string, 0, 1024 );

#ifdef LIBAKRYPT_HAVE_UNISTD_H
  if( code < 0 ) ak_snprintf( error_event_string, 1023, "[%d] %s(): %s (code: %d)",
                                                          getpid(), function, message, code );
   else ak_snprintf( error_event_string, 1023, "[%d] %s(): %s", getpid(), function, message );
#else
 #ifdef _MSC_VER
  if( code < 0 ) ak_snprintf( error_event_string, 1023, "[%d] %s(): %s (code: %d)",
                                             GetCurrentProcessId(), function, message, code );
   else ak_snprintf( error_event_string, 1023, "[%d] %s(): %s",
                                                   GetCurrentProcessId(), function, message );
 #else
   #error Unsupported path to compile, sorry ...
 #endif
#endif
  ak_log_set_message( error_event_string );
 return ak_error_set_value( code );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \b Внимание. Функция экспортируется.
    \param code Код ошибки
    \param function Имя функции, вызвавшей ошибку
    \param format Форматная строка, в соответствии с которой формируется сообщение                 */
/* ----------------------------------------------------------------------------------------------- */
 int ak_error_message_fmt( const int code, const char *function, const char *format, ... )
{
  char message[256];
  va_list args;
  va_start( args, format );
  memset( message, 0, 256 );

 #ifdef _MSC_VER
  #if _MSC_VER > 1310
    _vsnprintf_s( message, 256, 256, format, args );
  #else
    _vsnprintf( message, 256, format, args );
  #endif
 #else
   vsnprintf( message, 256, format, args );
 #endif
   va_end( args );
 return ak_error_message( code, function, message );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция рассматривает область памяти, на которую указывает указатель ptr, как массив
    последовательно записанных байт фиксированной длины, создает в оперативной памяти строку и
    последовательно выводит в нее значения, хранящиеся в заданной области памяти.
    Значения выводятся в шестнадцатеричной системе счисления.

    Пример использования.
  \code
    ak_uint8 data[5] = { 1, 2, 3, 4, 5 };
    ak_uint8 *str = ak_ptr_to_hexstr( data, 5, ak_false );
    printf("%s\n", str );
    free(str);
  \endcode

    @param ptr Указатель на область памяти
    @param ptr_size Размер области памяти (в байтах)
    @param reverse Последовательность вывода байт в строку. Если reverse равно \ref ak_false,
    то байты выводятся начиная с младшего к старшему.  Если reverse равно \ref ak_true, то байты
    выводятся начиная от старшего к младшему (такой способ вывода принят при стандартном выводе
    чисел: сначала старшие разряды, потом младшие).

    @return Функция возвращает указатель на созданную строку, которая должна быть позднее удалена
    пользователем с помощью вызова функции free(). В случае ошибки конвертации возвращается NULL.
    Код ошибки может быть получен с помощью вызова функции ak_error_get_code()                     */
/* ----------------------------------------------------------------------------------------------- */
 char *ak_ptr_to_hexstr( const ak_pointer ptr, const size_t ptr_size, const ak_bool reverse )
{
  char *nullstr = NULL;
  size_t len = 1 + (ptr_size << 1);

  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to data" );
    return NULL;
  }
  if( ptr_size <= 0 ) {
    ak_error_message( ak_error_zero_length, __func__ , "using data with zero or negative length" );
    return NULL;
  }

  if(( nullstr = (char *) malloc( len )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ , "incorrect memory allocation" );
  }
    else {
      size_t idx = 0, js = 0, start = 0, offset = 2;
      ak_uint8 *data = ( ak_uint8 * ) ptr;

      memset( nullstr, 0, len );
      if( reverse ) { // движение в обратную сторону - от старшего байта к младшему
        start = len-3; offset = -2;
      }
      for( idx = 0, js = start; idx < ptr_size; idx++, js += offset ) {
        char str[4];
        ak_snprintf( str, 3, "%02X", data[idx] );
        memcpy( nullstr+js, str, 2 );
      }
    }
 return nullstr;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция рассматривает область памяти, на которую указывает указатель ptr, как массив
    последовательно записанных байт фиксированной длины.
    Символьная (шестнадцатеричная) форма записи массива ptr помещается в заранее выделенный массив out.
    Если длины недостаточно, то возбуждается ошибка.

    Пример использования.
  \code
    ak_uint8 data[5] = { 1, 2, 3, 4, 5 };
    ak_uint8 data_out[12];

    if( ak_ptr_to_hexstr_static( data, 5, data_out, 12, ak_false ) == ak_error_ok )
      printf("%s\n", data_out );
  \endcode

    @param ptr Указатель на область памяти
    @param ptr_size Размер области памяти (в байтах)
    @param out Указатель на область памяти, в которую записывается символьное представление данных
    @param out_size Размер области памяти (в байтах); должен быть не менее, чем
    величина 1 + 2*`ptr_size`.

    @param reverse Последовательность вывода байт в строку. Если reverse равно \ref ak_false,
    то байты выводятся начиная с младшего к старшему.  Если reverse равно \ref ak_true, то байты
    выводятся начиная от старшего к младшему (такой способ вывода принят при стандартном выводе
    чисел: сначала старшие разряды, потом младшие).

    @return Если преобразование прошло успешно, возвращается \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_ptr_to_hexstr_static( const ak_pointer ptr, const size_t ptr_size,
                                     ak_pointer out, const size_t out_size, const ak_bool reverse )
{
  ak_uint8 *data = ( ak_uint8 * ) ptr;
  size_t len = 1 + (ptr_size << 1);
  size_t idx = 0, js = 0, start = 0, offset = 2;

  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                     "using null pointer to data" );
  if( ptr_size <= 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                        "using data with zero or negative length" );
  if( out_size < len ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                                 "using small size output buffer" );
  memset( out, 0, len );
  if( reverse ) { // движение в обратную сторону - от старшего байта к младшему
    start = len-3; offset = -2;
  }
  for( idx = 0, js = start; idx < ptr_size; idx++, js += offset ) {
     char str[4];
     ak_snprintf( str, 3, "%02X", data[idx] );
     memcpy( (ak_uint8 *)out+js, str, 2 );
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Конвертация символа в целочисленное значение                                            */
/* ----------------------------------------------------------------------------------------------- */
 inline static ak_uint32 ak_xconvert( const char c )
{
    switch( c )
   {
      case 'a' :
      case 'A' : return 10;
      case 'b' :
      case 'B' : return 11;
      case 'c' :
      case 'C' : return 12;
      case 'd' :
      case 'D' : return 13;
      case 'e' :
      case 'E' : return 14;
      case 'f' :
      case 'F' : return 15;
      case '0' : return 0;
      case '1' : return 1;
      case '2' : return 2;
      case '3' : return 3;
      case '4' : return 4;
      case '5' : return 5;
      case '6' : return 6;
      case '7' : return 7;
      case '8' : return 8;
      case '9' : return 9;
      default : ak_error_set_value( ak_error_undefined_value ); return 0;
 }
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция преобразует строку символов, содержащую последовательность шестнадцатеричных цифр,
    в массив данных.

    @param hexstr Строка символов.
    @param ptr Указатель на область памяти (массив), в которую будут размещаться данные.
    @param size Максимальный размер памяти (в байтах), которая может быть помещена в массив.
    Если исходная строка требует больший размер, то возбуждается ошибка.
    @param reverse Последовательность считывания байт в память. Если reverse равно \ref ak_false
    то первые байты строки (с младшими индексами) помещаются в младшие адреса, а старшие байты -
    в старшие адреса памяти. Если reverse равно \ref ak_true, то производится разворот,
    то есть обратное преобразование при котором элементы строки со старшиси номерами помещаются
    в младшие разряды памяти (такое представление используется при считывании больших целых чисел).

    @return В случае успеха возвращается ноль. В противном случае, в частности,
                      когда длина строки превышает размер массива, возвращается код ошибки.        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hexstr_to_ptr( const char *hexstr, ak_pointer ptr, const size_t size, const ak_bool reverse )
{
  int i = 0;
  ak_uint8 *bdata = ptr;
  size_t len = 0;

  if( hexstr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                             "using null pointer to a hex string" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                 "using null pointer to a buffer" );
  if( size == 0 ) return ak_error_message( ak_error_zero_length, __func__,
                                                          "using zero value for length of buffer" );
  len = strlen( hexstr );
  if( len&1 ) len++;
  len >>= 1;
  if( size < len ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                               "using a buffer with small length" );

  memset( ptr, 0, size ); // перед конвертацией мы обнуляем исходные данные
  ak_error_set_value( ak_error_ok );
  if( reverse ) {
    for( i = strlen( hexstr )-2, len = 0; i >= 0 ; i -= 2, len++ ) {
       bdata[len] = (ak_xconvert( hexstr[i] ) << 4) + ak_xconvert( hexstr[i+1] );
    }
    if( i == -1 ) bdata[len] = ak_xconvert( hexstr[0] );
  } else {
        for( i = 0, len = 0; i < (int) strlen( hexstr ); i += 2, len++ ) {
           bdata[len] = (ak_xconvert( hexstr[i] ) << 4);
           if( i < (int) strlen( hexstr )-1 ) bdata[len] += ak_xconvert( hexstr[i+1] );
        }
    }
 return ak_error_get_value();
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция сравнивает две области памяти одного размера, на которые указывают аргументы функции.

    Пример использования функции (результат выполнения функции должен быть \ref ak_false).
  \code
    ak_uint8 data_left[5] = { 1, 2, 3, 4, 5 };
    ak_uint8 data_right[5] = { 1, 2, 3, 4, 6 };

    if( ak_ptr_is_equal( data_left, data_right, 5 )) printf("Is equal");
     else printf("Not equal");
  \endcode

    @param left Указатель на область памяти, участвующей в сравнении слева.
    @param right Указатель на область пямяти, участвующей в сравнении справа.
    @param size Размер области, для которой производяится сравнение.
    @return Если данные идентичны, то возвращается \ref ak_true.
    В противном случае, а также в случае возникновения ошибки, возвращается \ref ak_false.
    Код шибки может быть получен с помощью выщова функции ak_error_get_value().                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_ptr_is_equal( const ak_pointer left, const ak_pointer right, const size_t size )
{
  size_t i = 0;
  ak_bool result = ak_true;
  ak_uint8 *lp = left, *rp = right;

  if(( left == NULL ) || ( right == NULL )) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer" );
    return ak_false;
  }

  for( i = 0; i < size; i++ )
     if( lp[i] != rp[i] ) result = ak_false;

  return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param pass Строка, в которую будет помещен пароль. Память под данную строку должна быть
    выделена заранее. Если в данной памяти хранились какие-либо данные, то они будут полностью
    уничтожены.
    @param psize Максимально возможная длина пароля. При этом величина psize-1 задает
    максимально возможную длиину пароля, поскольку пароль всегда завершается нулевым символом.
    Таким образом длина пароля, после его чтения, может быть получена с помощью функции strlen().

    \b Внимание. В случае ввода пароля нулевой длины функция возвращает ошибку с кодом
    \ref ak_error_terminal

    @return В случае успеха функция возвращает значение \ref ak_error_ok. В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_password_read( char *pass, const size_t psize )
{
   size_t len = 0;
   int error = ak_error_ok;

 #ifndef LIBAKRYPT_HAVE_TERMIOS_H
  #ifdef _WIN32
   char c = 0;
   DWORD mode, count;
   HANDLE ih = GetStdHandle( STD_INPUT_HANDLE  );
   if( !GetConsoleMode( ih, &mode ))
     return ak_error_message( ak_error_terminal, __func__, "not connected to a console" );
   SetConsoleMode( ih, mode & ~( ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT ));

   memset( pass, 0, psize );
   while( ReadConsoleA( ih, &c, 1, &count, NULL) && (c != '\r') && (c != '\n') && (len < psize-1) ) {
     pass[len]=c;
     len++;
   }
   pass[len]=0;

   /* восстанавливаем настройки консоли */
   SetConsoleMode( ih, mode );
   if(( len = strlen( pass )) < 1 )
     return ak_error_message( ak_error_zero_length, __func__ , "input a very short password");
   return error;

  #endif
   return ak_error_undefined_function;

 #else
  /* обрабатываем терминал */
   struct termios ts, ots;

   tcgetattr( STDIN_FILENO, &ts);   /* получаем настройки терминала */
   ots = ts;
   ts.c_cc[ VTIME ] = 0;
   ts.c_cc[ VMIN  ] = 1;
   ts.c_iflag &= ~( BRKINT | INLCR | ISTRIP | IXOFF ); // ICRNL | IUTF8
   ts.c_iflag |=    IGNBRK;
   ts.c_oflag &= ~( OPOST );
   ts.c_cflag &= ~( CSIZE | PARENB);
   ts.c_cflag |=    CS8;
   ts.c_lflag &= ~( ECHO | ICANON | IEXTEN | ISIG );
   tcsetattr( STDIN_FILENO, TCSAFLUSH, &ts );
   tcgetattr( STDIN_FILENO, &ts ); /* проверяем, что все установилось */
   if( ts.c_lflag & ECHO ) {
        ak_error_message( error = ak_error_terminal, __func__, "failed to turn off echo" );
        goto lab_exit;
   }

   memset( pass, 0, psize );
   fgets( pass, psize, stdin );
   if(( len = strlen( pass )) < 2 )
     ak_error_message( error = ak_error_zero_length, __func__ , "input a very short password");
   if( len > 0 ) pass[len-1] = 0;
    else pass[0] = 0;

  /* убираем за собой и восстанавливаем настройки */
   lab_exit: tcsetattr( STDIN_FILENO, TCSANOW, &ots );
   return error;
 #endif

 /* некорректный путь компиляции исходного текста функции */
 return ak_error_undefined_function;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example example-hello.c                                                                       */
/*! \example example-log.c                                                                         */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                     ak_tools.c  */
/* ----------------------------------------------------------------------------------------------- */
