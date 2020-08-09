/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2004 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_file.с                                                                                 */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakbase.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_SYSSTAT_H
 #include <sys/stat.h>
#endif
#ifdef AK_HAVE_ERRNO_H
 #include <errno.h>
#endif
#ifdef AK_HAVE_UNISTD_H
 #include <unistd.h>
#endif
#ifdef AK_HAVE_FCNTL_H
 #include <fcntl.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 int ak_file_or_directory( const char *filename )
{
 struct stat st;

  if(( !filename ) || ( stat( filename, &st )))  return 0;
  if( S_ISREG( st.st_mode )) return DT_REG;
  if( S_ISDIR( st.st_mode )) return DT_DIR;

 return 0;
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
      case EACCES:
        if( ak_log_get_level() >= ak_log_maximum )
          ak_error_message_fmt( ak_error_access_file, __func__,
                                 "incorrect access to file %s [%s]", filename, strerror( errno ));
        return ak_error_access_file;
      default:
        if( ak_log_get_level() >= ak_log_maximum )
          ak_error_message_fmt( ak_error_open_file, __func__ ,
                                     "wrong opening a file %s [%s]", filename, strerror( errno ));
        return ak_error_open_file;
    }
  }

 /* заполняем данные */
  file->size = ( ak_int64 )st.st_size;
 #ifdef AK_HAVE_WINDOWS_H
  if(( file->hFile = CreateFile( filename,   /* name of the write */
                     GENERIC_READ,           /* open for reading */
                     0,                      /* do not share */
                     NULL,                   /* default security */
                     OPEN_EXISTING,          /* open only existing file */
                     FILE_ATTRIBUTE_NORMAL,  /* normal file */
                     NULL )                  /* no attr. template */
      ) == INVALID_HANDLE_VALUE ) {
      if( ak_log_get_level() >= ak_log_maximum )
        ak_error_message_fmt( ak_error_open_file, __func__,
                                     "wrong opening a file %s [%s]", filename, strerror( errno ));
      return ak_error_open_file;
  }
  file->blksize = 4096;
 #else
  if(( file->fd = open( filename, O_SYNC|O_RDONLY )) < 0 ) {
    if( ak_log_get_level() >= ak_log_maximum )
      ak_error_message_fmt( ak_error_open_file, __func__ ,
                                     "wrong opening a file %s [%s]", filename, strerror( errno ));
    return ak_error_open_file;
  }
  file->blksize = ( ak_int64 )st.st_blksize;
 #endif

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_file_create_to_write( ak_file file, const char *filename )
{
 #ifndef AK_HAVE_WINDOWS_H
  struct stat st;
 #endif

 /* необходимые проверки */
  if(( file == NULL ) || ( filename == NULL ))
    return ak_error_message( ak_error_null_pointer, __func__, "using null pointer" );

  file->size = 0;
 #ifdef AK_HAVE_WINDOWS_H
  if(( file->hFile = CreateFile( filename,   /* name of the write */
                     GENERIC_WRITE,          /* open for writing */
                     0,                      /* do not share */
                     NULL,                   /* default security */
                     CREATE_ALWAYS,          /* create new file only */
                     FILE_ATTRIBUTE_NORMAL,  /* normal file */
                     NULL )                  /* no attr. template */
     ) == INVALID_HANDLE_VALUE )
      return ak_error_message_fmt( ak_error_create_file, __func__,
                                    "wrong creation a file %s [%s]", filename, strerror( errno ));
   file->blksize = 4096;

 #else  /* мы устанавливаем минимальные права: чтение и запись только для владельца */
  if(( file->fd = creat( filename, S_IRUSR | S_IWUSR )) < 0 )
    return ak_error_message_fmt( ak_error_create_file, __func__,
                                   "wrong creation a file %s [%s]", filename, strerror( errno ));
  if( fstat( file->fd, &st )) {
    close( file->fd );
    return ak_error_message_fmt( ak_error_access_file,  __func__,
                                "incorrect access to file %s [%s]", filename, strerror( errno ));
  } else file->blksize = ( ak_int64 )st.st_blksize;
 #endif

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_file_close( ak_file file )
{
   file->size = 0;
   file->blksize = 0;
  #ifdef AK_HAVE_WINDOWS_H
   CloseHandle( file->hFile);
  #else
   if( close( file->fd ) != 0 ) return ak_error_message_fmt( ak_error_close_file, __func__ ,
                                                 "wrong closing a file [%s]", strerror( errno ));
  #endif
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 ssize_t ak_file_read( ak_file file, ak_pointer buffer, size_t size )
{
 #ifdef AK_HAVE_WINDOWS_H
  DWORD dwBytesReaden = 0;
  BOOL bErrorFlag = ReadFile( file->hFile, buffer, ( DWORD )size,  &dwBytesReaden, NULL );
  if( bErrorFlag == FALSE ) {
    ak_error_message( ak_error_read_data, __func__, "unable to read from file");
    return 0;
  } else return ( ssize_t ) dwBytesReaden;
 #else
  return read( file->fd, buffer, size );
 #endif
}

/* ----------------------------------------------------------------------------------------------- */
 ssize_t ak_file_write( ak_file file, ak_const_pointer buffer, size_t size )
{
 #ifdef AK_HAVE_WINDOWS_H
  DWORD dwBytesWritten = 0;
  BOOL bErrorFlag = WriteFile( file->hFile, buffer, ( DWORD )size,  &dwBytesWritten, NULL );
  if( bErrorFlag == FALSE ) {
    ak_error_message( ak_error_write_data, __func__, "unable to write to file");
    return -1;
  } else return ( ssize_t ) dwBytesWritten;
 #else
   ssize_t wb = write( file->fd, buffer, size );
   if( wb == -1 ) ak_error_message_fmt( ak_error_write_data, __func__,
                                                "unable to write to file (%s)", strerror( errno ));
  return wb;
 #endif
}

/* ----------------------------------------------------------------------------------------------- */
 ssize_t ak_file_printf( ak_file outfile, const char *format, ... )
{
  va_list args;
  ssize_t result = 0;
  char static_buffer[1024];
  va_start( args, format );

 /* формируем строку (дублируем код функции ak_snprintf) */
 #ifdef _MSC_VER
  #if _MSC_VER > 1310
    _vsnprintf_s( static_buffer,
                  sizeof( static_buffer ),
                  sizeof( static_buffer ), format, args );
  #else
    _vsnprintf( static_buffer,
                sizeof( static_buffer ), format, args );
  #endif
 #else
  vsnprintf( static_buffer, sizeof( static_buffer ), format, args );
 #endif
  va_end( args );

 /* выводим ее в файл как последовательность байт */
  result = ak_file_write( outfile, static_buffer, strlen( static_buffer ));
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_file.c  */
/* ----------------------------------------------------------------------------------------------- */
