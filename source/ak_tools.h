/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_tools.h                                                                                */
/*  - содержит описания служебных функций и переменных, не экспортируемых за пределы библиотеки    */
/* ----------------------------------------------------------------------------------------------- */
 #ifndef    __AK_TOOLS_H__
 #define    __AK_TOOLS_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

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
/*! \brief Структура данных для хранения дескриптора и параметров файла (используется переносимая реализация через libc). */
 typedef struct file {
 /*! \brief Дескриптор файла. */
  FILE *fp;
 /*! \brief Размер файла. */
  ak_uint64 size;
 /*! \brief Размер блока для оптимального чтения с жесткого диска. */
  ak_uint32 blksize;
 } *ak_file;

/* ----------------------------------------------------------------------------------------------- */
 int ak_file_open_to_read( ak_file , const char * );
 int ak_file_create_to_write( ak_file , const char * );

/*! \brief Функция закрывает файл с заданным дескриптором. */
 int ak_file_close( ak_file );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция устанавливает домашний каталог пользователя. */
 int ak_libakrypt_get_home_path( char *, const size_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Неэкспортируемая функция установления уровня аудита. */
 int ak_log_set_level( int );

/*! \brief Функция устанавливает значение опции с заданным именем. */
 int ak_libakrypt_set_option( const char *name, const ak_int64 value );
/*! \brief Функция возвращает значение опции с заданным именем. */
 ak_int64 ak_libakrypt_get_option( const char *name );
/*! \brief Функция считывает настройки (параметры) библиотеки из файла libakrypt.conf */
 ak_bool ak_libakrypt_load_options( void );

 #endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_libakrypt.h  */
/* ----------------------------------------------------------------------------------------------- */
