/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  ak_tools.h                                                                                     */
/*  Файл содержит описания служебных функций и переменных, не экспортируемых за пределы библиотеки */
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
 typedef struct file {
  /*! \brief Дескриптор файла */
  int fd;
  /*! \brief Информация о параметрах файла */
  struct stat st;
 } *ak_file;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция проверяет наличие данного файла. */
 ak_bool ak_file_is_exist( ak_file , const char *, ak_bool );
/*! \brief Функция создает заданный файл c правами на чтение и запись. */
 int ak_file_create( ak_file , const char * );
/*! \brief Функция закрывает файл с заданным дескриптором. */
 int ak_file_close( ak_file );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция устанавливает домашний каталог пользователя. */
 int ak_libakrypt_get_home_path( char *, const size_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Неэкспортируемая функция установления уровня аудита. */
 int ak_log_set_level( int );

/*! \brief Функция устанавливает значение опции с заданным именем. */
 int ak_libakrypt_set_option( const char *name, const ak_int32 value );
/*! \brief Функция возвращает значение опции с заданным именем. */
 ak_int32 ak_libakrypt_get_option( const char *name );
/*! \brief Функция считывает настройки (параметры) библиотеки из файла libakrypt.conf */
 ak_bool ak_libakrypt_load_options( void );

 #endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_libakrypt.h  */
/* ----------------------------------------------------------------------------------------------- */
