/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл akrypt.c                                                                                  */
/*  - содержит объявления служебных функций консольного клиента                                    */
/* ----------------------------------------------------------------------------------------------- */
 #ifndef AKRYPT_H
 #define AKRYPT_H

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>
 #include <getopt.h>
 #ifdef _WIN32
  #include <tchar.h>
  #include <strsafe.h>
 #else
  #define TCHAR char
 #endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_SYSSTAT_H
 #include <sys/stat.h>
#endif
#ifdef LIBAKRYPT_HAVE_UNISTD_H
 #include <unistd.h>
#endif
#ifdef LIBAKRYPT_HAVE_DIRENT_H
 #include <dirent.h>
#endif
#ifdef LIBAKRYPT_HAVE_ERRNO_H
 #include <errno.h>
#endif
#ifdef LIBAKRYPT_HAVE_FNMATCH_H
 #include <fnmatch.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 #ifdef LIBAKRYPT_HAVE_LOCALE_H
  #include <locale.h>
 #endif
 #ifdef LIBAKRYPT_HAVE_LIBINTL_H
  #include <libintl.h>
  #define _( string ) gettext( string )
 #else
  #define _( string ) ( string )
 #endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef _MSC_VER
 #define	S_ISDIR(mode)  (((mode) & S_IFMT) == S_IFDIR)
 #define	S_ISREG(mode)  (((mode) & S_IFMT) == S_IFREG)
#endif
#ifndef DT_DIR
 #define DT_DIR (4)
#endif
#ifndef DT_REG
 #define DT_REG (8)
#endif

/* ----------------------------------------------------------------------------------------------- */
 #define akrypt_max_icode_size  (128)

/* ----------------------------------------------------------------------------------------------- */
 extern ak_function_log *audit;

/* ----------------------------------------------------------------------------------------------- */
/* определение функции для выполнения действий с заданным файлом */
 typedef int ( ak_function_find )( const TCHAR * , ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/* обход каталога с учетом заданной маски */
 int akrypt_find( const TCHAR *, const TCHAR *, ak_function_find *, ak_pointer , ak_bool );
/* проверка, является ли заданная стирока файлом или директорией */
 int akrypt_file_or_directory( const TCHAR * );

/* ----------------------------------------------------------------------------------------------- */
/* вывод очень короткой справки о программе */
 int akrypt_litehelp( void );
/* вывод длинной справки о программе */
 int akrypt_help( void );
/* проверка корректности заданной пользователем команды */
 ak_bool akrypt_check_command( const char *, TCHAR * );
/* вывод сообщений в заданный пользователем файл, а также в стандартный демон вывода сообщений */
 int akrypt_audit_function( const char * );
/* определение функции вывода сообщений о ходе выполнения программы */
 void akrypt_set_audit( TCHAR * );

/* ----------------------------------------------------------------------------------------------- */
/* реализации пользовательских команд */
 int akrypt_hash( int argc, TCHAR *argv[] );
 int akrypt_show( int argc, TCHAR *argv[] );

 #endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       akrypt.h  */
/* ----------------------------------------------------------------------------------------------- */
