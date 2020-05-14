/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл aktool.h                                                                                  */
/*  - содержит объявления служебных функций консольного клиента                                    */
/* ----------------------------------------------------------------------------------------------- */
 #ifndef AKTOOL_H
 #define AKTOOL_H

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>
 #include <getopt.h>
 #ifdef _WIN32
  #include <windows.h>
  #include <tchar.h>
 #else
  #define TCHAR char
 #endif

/* ----------------------------------------------------------------------------------------------- */
 #ifdef LIBAKRYPT_HAVE_STDIO_H
  #include <stdio.h>
 #else
  #error Library cannot be compiled without stdlib.h header
 #endif
 #ifdef LIBAKRYPT_HAVE_STDLIB_H
  #ifndef __USE_MISC
    #define __USE_MISC
  #endif
  #include <stdlib.h>
 #else
  #error Library cannot be compiled without stdlib.h header
 #endif
 #ifdef LIBAKRYPT_HAVE_STRING_H
  #ifndef __USE_POSIX
    #define __USE_POSIX
  #endif
  #include <string.h>
 #else
  #error Library cannot be compiled without string.h header
 #endif
 #ifdef LIBAKRYPT_HAVE_STDARG_H
  #include <stdarg.h>
 #else
  #error Library cannot be compiled without stdarg.h header
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
 #ifdef LIBAKRYPT_HAVE_FCNTL_H
  #include <fcntl.h>
 #endif
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
 #define aktool_max_icode_size    (128)

/* ----------------------------------------------------------------------------------------------- */
 #define aktool_max_password_len  (256)

/* ----------------------------------------------------------------------------------------------- */
 extern ak_function_log *audit;
 extern char audit_filename[1024];

/* ----------------------------------------------------------------------------------------------- */
/* определение функции для выполнения действий с заданным файлом */
 typedef int ( ak_function_find )( const TCHAR * , ak_pointer );
/* определение функции, передаваемой в качестве аргумента в функцию построчного чтения файлов. */
 typedef int ( ak_file_read_function ) ( char * , ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/* обход каталога с учетом заданной маски */
 int aktool_find( const TCHAR *, const TCHAR *, ak_function_find *, ak_pointer , bool_t );
/* проверка, является ли заданная стирока файлом или директорией */
 int aktool_file_or_directory( const TCHAR * );

/* ----------------------------------------------------------------------------------------------- */
/* вывод очень короткой справки о программе */
 int aktool_litehelp( void );
 int aktool_version( void );
/* вывод длинной справки о программе */
 int aktool_help( void );
/* вывод информации об ощих опциях */
 int aktool_print_common_options();
/* проверка корректности заданной пользователем команды */
 bool_t aktool_check_command( const char *, TCHAR * );
/* вывод сообщений в заданный пользователем файл, а также в стандартный демон вывода сообщений */
 int aktool_audit_function( const char * );
/* определение функции вывода сообщений о ходе выполнения программы */
 void aktool_set_audit( TCHAR * );
/* построчное чтение файла и применение к каждой строке заданной функции */
 int ak_file_read_by_lines( const char * , ak_file_read_function * , ak_pointer );
/* вывод в консоль строки с сообщением об ошибке */
 void aktool_error( const char *format, ... );

/* ----------------------------------------------------------------------------------------------- */
/* реализации пользовательских команд */
 int aktool_icode( int argc, TCHAR *argv[] );
 int aktool_show( int argc, TCHAR *argv[] );
 int aktool_asn1( int argc, TCHAR *argv[] );
 int aktool_key( int argc, TCHAR *argv[] );

 #endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       aktool.h  */
/* ----------------------------------------------------------------------------------------------- */
