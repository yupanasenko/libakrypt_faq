/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл aktool.h                                                                                  */
/*  - содержит объявления служебных функций консольного клиента                                    */
/* ----------------------------------------------------------------------------------------------- */
 #ifndef AKTOOL_H
 #define AKTOOL_H

/* ----------------------------------------------------------------------------------------------- */
 #include <getopt.h>
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_LOCALE_H
 #include <locale.h>
#endif
#ifdef AK_HAVE_LIBINTL_H
 #include <libintl.h>
 #define _( string ) gettext( string )
#else
 #define _( string ) ( string )
#endif
#ifdef AK_HAVE_TIME_H
 #include <time.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 #define aktool_password_max_length (256)

/* ----------------------------------------------------------------------------------------------- */
#if defined(__unix__) || defined(__APPLE__)
  #define aktool_default_generator "dev-random"
#else
  #ifdef AK_HAVE_WINDOWS_H
    #define aktool_default_generator "winrtl"
  #else
    #define aktool_default_generator "lcg"
  #endif
#endif

/* ----------------------------------------------------------------------------------------------- */
 extern int aktool_log_level;
 extern bool_t aktool_openssl_compability;
 extern char audit_filename[1024];
 extern bool_t aktool_hex_password_input;

/* ----------------------------------------------------------------------------------------------- */
/* вывод очень короткой справки о программе */
 int aktool_litehelp( void );
/* вывод версии */
 int aktool_version( void );
/* вывод длинной справки о программе */
 int aktool_help( void );
/* вывод информации об ощих опциях */
 int aktool_print_common_options();
/* проверка корректности заданной пользователем команды */
 bool_t aktool_check_command( const char *, tchar * );
/* вывод сообщений в заданный пользователем файл, а также в стандартный демон вывода сообщений */
 int aktool_audit_function( const char * );
/* определение функции вывода сообщений о ходе выполнения программы */
 void aktool_set_audit( tchar * );
/* вывод в консоль строки с сообщением об ошибке */
 void aktool_error( const char *format, ... );
/* общий для всех подпрограмм запуск процедуры инициализации билиотеки */
 bool_t aktool_create_libakrypt( void );
/* общий для всех подпрограмм запуск процедуры остановки билиотеки */
 int aktool_destroy_libakrypt( void );

/* функция однократного чтения пароля из консоли */
 ssize_t aktool_key_load_user_password( char * , const size_t );
/* функция двукратного чтения пароля из консоли */
 ssize_t aktool_key_load_user_password_twice( char * , const size_t );

/* ----------------------------------------------------------------------------------------------- */
/* реализации пользовательских команд */
 int aktool_show( int argc, tchar *argv[] );
 int aktool_test( int argc, tchar *argv[] );
 int aktool_asn1( int argc, tchar *argv[] );
 int aktool_key( int argc, tchar *argv[] );
 int aktool_icode( int argc, tchar *argv[] );

 typedef enum { do_nothing, do_encrypt, do_decrypt } encrypt_t;
 int aktool_encrypt( int argc, tchar *argv[], encrypt_t work );

 #endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       aktool.h  */
/* ----------------------------------------------------------------------------------------------- */
