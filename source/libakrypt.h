/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2017 by Axel Kenzo, axelkenzo@mail.ru                                     */
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
/*   libakrypt.h                                                                                   */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __LIBAKRYPT_H__
#define    __LIBAKRYPT_H__

/* ----------------------------------------------------------------------------------------------- */
#ifdef DLL_EXPORT
 #define building_dll
#endif
#ifdef _MSC_VER
 #define building_dll
#endif
/* ----------------------------------------------------------------------------------------------- */
/* Обрабатываем вариант библиотеки для работы под Windows (Win32)                                  */
#ifdef building_dll
 #define dll_export __declspec (dllexport)
#else
/* ----------------------------------------------------------------------------------------------- */
/* Для остальных операционных систем символ теряет свой смысл ;)                                   */
 #define dll_export
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef _MSC_VER
 #pragma warning (disable : 4711)
 #pragma warning (disable : 4820)
 #pragma warning (disable : 4996)
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
 #include <pthread.h>
 #include <sys/types.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef _MSC_VER
 #include <io.h>
 #include <windows.h>
 #include <process.h>
 typedef signed char ak_int8;
 typedef unsigned char ak_uint8;
 typedef __int32 ak_int32;
 typedef unsigned __int32 ak_uint32;
 typedef __int64 ak_int64;
 typedef unsigned __int64 ak_uint64;
#endif
#ifdef __MINGW32__
 typedef __int8 ak_int8;
 typedef unsigned __int8 ak_uint8;
 typedef __int32 ak_int32;
 typedef unsigned __int32 ak_uint32;
 typedef __int64 ak_int64;
 typedef unsigned __int64 ak_uint64;
#endif
#ifdef MSYS
 typedef int8_t ak_int8;
 typedef u_int8_t ak_uint8;
 typedef int32_t ak_int32;
 typedef u_int32_t ak_uint32;
 typedef int64_t ak_int64;
 typedef u_int64_t ak_uint64;
 int snprintf(char *str, size_t size, const char *format, ... );
#endif
#ifdef __linux__
 typedef int8_t ak_int8;
 typedef u_int8_t ak_uint8;
 typedef int32_t ak_int32;
 typedef u_int32_t ak_uint32;
 typedef int64_t ak_int64;
 typedef u_int64_t ak_uint64;
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Определение булева типа, принимающего значения либо истина, либо ложь. */
 typedef enum { ak_false, ak_true } ak_bool;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Генератор псевдо-случайных чисел. */
 struct random;
/*! \brief Контекст генератора псевдослучайных чисел. */
 typedef struct random *ak_random;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Указатель на произвольный объект библиотеки. */
 typedef void *ak_pointer;
/*! \brief Стандартная для языка С функция выделения памяти. */
 typedef ak_pointer ( ak_function_alloc )( size_t );
/*! \brief Стандартная для языка С функция освобождения памяти. */
 typedef void ( ak_function_free )( ak_pointer );
/*! \brief Функция, возвращающая NULL после освобождения памяти. */
 typedef ak_pointer ( ak_function_free_object )( ak_pointer );
/*! \brief Стандартная для языка С функция перераспределения памяти. */
 typedef ak_pointer ( ak_function_realloc )( ak_pointer , size_t );
/*! \brief Пользовательская функция аудита. */
 typedef int ( ak_function_log )( const char * );

/* ----------------------------------------------------------------------------------------------- */
 #define ak_error_ok                            (0)
 #define ak_error_out_of_memory                (-1)
 #define ak_error_null_pointer                 (-2)
 #define ak_error_zero_length                  (-3)
 #define ak_error_wrong_length                 (-4)
 #define ak_error_undefined_value              (-5)
 #define ak_error_undefined_function           (-6)
 #define ak_error_access_file                 (-10)
 #define ak_error_open_file                   (-11)
 #define ak_error_close_file                  (-12)
 #define ak_error_read_data                   (-13)
 #define ak_error_write_data                  (-14)

/* ----------------------------------------------------------------------------------------------- */
 #define ak_null_string                  ("(null)")

 #define ak_log_none                            (0)
 #define ak_log_standard                        (1)
 #define ak_log_maximum                         (2)

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает уровень аудита библиотеки. */
 dll_export int ak_log_get_level( void );
/*! \brief Прямой вывод сообщения аудита. */
 dll_export int ak_log_set_message( const char * );
/*! \brief Явное задание функции аудита. */
 dll_export int ak_log_set_function( ak_function_log * );
#ifdef HAVE_SYSLOG_H
 /*! \brief Функиция вывода сообщения об ошибке с помощью демона операционной системы. */
 int ak_function_log_syslog( const char * );
#endif
/*! \brief Функция вывода сообщения об ошибке в стандартный канал вывода ошибок. */
 dll_export int ak_function_log_stderr( const char * );
/*! \brief Вывод сообщений о возникшей в процессе выполнения ошибке. */
 dll_export int ak_error_message( const int, const char *, const char * );
/*! \brief Вывод сообщений о возникшей в процессе выполнения ошибке. */
 dll_export int ak_error_message_fmt( const int , const char *, const char *, ... );
/*! \brief Функция устанавливает значение переменной, хранящей ошибку выполнения программы. */
 dll_export int ak_error_set_value( const int );
/*! \brief Функция возвращает код последней ошибки выполнения программы. */
 dll_export int ak_error_get_value( void );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает константный указатель NULL-строку с текущей версией библиотеки. */
 dll_export const char *ak_libakrypt_version( void );
/*! \brief Функция инициализации и тестирования криптографических механизмов библиотеки. */
 dll_export int ak_libakrypt_create( ak_function_log * );
/*! \brief Функция останавки поддержки криптографических механизмов. */
 dll_export int ak_libakrypt_destroy( void );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание линейного конгруэнтного генератора псевдо-случайных чисел. */
 dll_export ak_random ak_random_new_lcg( void );
/*! \brief Cоздание генератора, считывающего случайные значения из заданного файла. */
 dll_export ak_random ak_random_new_file( const char *filename );
#ifdef _WIN32
/*! \brief Интерфейс доступа к псевдо-случайному генератору ОС Windows. */
 dll_export ak_random ak_random_new_winrtl( void );
#endif
/*! \brief Инициализация генератора значением другого псевдо-случайного генератора. */
 dll_export int ak_random_randomize( ak_random );
/*! \brief Инициализация генератора данными, содержащимися в заданной области памяти. */
 dll_export int ak_random_randomize_ptr( ak_random, const ak_pointer, const size_t );
/*! \brief Заполнение заданного массива псевдо случайными данными. */
 dll_export int ak_random_ptr( ak_random, const ak_pointer, const size_t );
/*! \brief Уничтожение генератора псевдо-случайных чисел. */
 dll_export ak_pointer ak_random_delete( ak_pointer );
/*! \brief Выработка одного псевдо-случайного байта. */
 dll_export ak_uint8 ak_random_uint8( ak_random );
/*! \brief Выработка одного псевдо-случайного слова размером 8 байт (64 бита). */
 dll_export ak_uint64 ak_random_uint64( ak_random );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание строки символов, содержащей значение заданной области памяти. */
 dll_export char *ak_ptr_to_hexstr( const ak_pointer , const size_t , const ak_bool );
/*! \brief Конвертация строки шестнадцатеричных символов в массив данных. */
 dll_export int ak_hexstr_to_ptr( const char *, ak_pointer , const size_t , const ak_bool );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Обобщенная реализация функции snprintf для различных компиляторов. */
 dll_export int ak_snprintf( char *str, size_t size, const char *format, ... );

/* ----------------------------------------------------------------------------------------------- */
#ifndef __STDC_VERSION__
  #define inline
  int snprintf(char *str, size_t size, const char *format, ... );
#endif
#ifdef _MSC_VER
 #define __func__  __FUNCTION__
#endif
#ifndef _WIN32
 #ifndef O_BINARY
   #define O_BINARY  ( 0x0 )
 #endif
#endif

#define ak_max(x,y) ((x) > (y) ? (x) : (y))
#define ak_min(x,y) ((x) < (y) ? (x) : (y))

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                     libakrypt.h */
/* ----------------------------------------------------------------------------------------------- */
