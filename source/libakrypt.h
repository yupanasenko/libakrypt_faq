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
/*! \brief Указатель на произвольный объект библиотеки. */
 typedef void *ak_pointer;
/*! \brief Дескриптор произвольного объекта библиотеки. */
 typedef ak_int64 ak_handle;
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
/*! \brief Результат, говорящий об отсутствии ошибки. */
 #define ak_error_ok                            (0)
/*! \brief Ошибка выделения оперативной памяти. */
 #define ak_error_out_of_memory                (-1)
/*! \brief Ошибка , возникающая при доступе или передаче в качестве аргумента функции null указателя. */
 #define ak_error_null_pointer                 (-2)
/*! \brief Ошибка, возникащая при передаче аргументов функции или выделении памяти нулевой длины. */
 #define ak_error_zero_length                  (-3)
/*! \brief Ошибка, возникающая при обработке данных ошибочной длины. */
 #define ak_error_wrong_length                 (-4)
/*! \brief Использование неопределенного значения. */
 #define ak_error_undefined_value              (-5)
/*! \brief Использование неопределенного указателя на функцию (вызов null указателя). */
 #define ak_error_undefined_function           (-6)
/*! \brief Ошибка доступа к файлу (устройству). */
 #define ak_error_access_file                 (-10)
/*! \brief Ошибка открытия файла (устройства). */
 #define ak_error_open_file                   (-11)
/*! \brief Ошибка закрытия файла (устройства). */
 #define ak_error_close_file                  (-12)
/*! \brief Ошибка чтения из файла (устройства). */
 #define ak_error_read_data                   (-13)
/*! \brief Ошибка записи в файл (устройство). */
 #define ak_error_write_data                  (-14)
/*! \brief Неверное значение дескриптора объекта. */
 #define ak_error_wrong_handle                (-15)
/*! \brief Ошибка возникающая в случае неправильного значения размера структуры хранения контекстов. */
 #define ak_error_context_manager_size        (-16)
/*! \brief Ошибка возникающая при превышении числа возможных элементов структуры хранения контекстов. */
 #define ak_error_context_manager_max_size    (-17)
/*! \brief */
 #define ak_error_oid                         (-18)
/*! \brief Неверный тип криптографического механизма. */
 #define ak_error_oid_engine                  (-19)
/*! \brief Неверный режим использования криптографического механизма. */
 #define ak_error_oid_mode                    (-20)
/*! \brief Ошибочное или не определенное имя криптографического механизма. */
 #define ak_error_oid_name                    (-21)
/*! \brief Ошибочный или неопределенный идентификатор криптографического механизма. */
 #define ak_error_oid_id                      (-22)
/*! \brief Ошибочный индекс идентификатора криптографического механизма. */
 #define ak_error_oid_index                   (-23)

/* ----------------------------------------------------------------------------------------------- */
 #define ak_null_string                  ("(null)")

 #define ak_log_none                            (0)
 #define ak_log_standard                        (1)
 #define ak_log_maximum                         (2)

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тип криптографического механизма. */
 typedef enum {
   /*! \brief неопределенный механизм, может возвращаться как ошибка */
     undefined_engine,
   /*! \brief идентификатор */
     identifier,
   /*! \brief симметричный шифр (блочный алгоритм)  */
     block_cipher,
   /*! \brief симметричный шифр (поточный алгоритм)  */
     stream_cipher,
   /*! \brief схема гибридного шифрования */
     hybrid_cipher,
   /*! \brief функция хеширования */
     hash_function,
   /*! \brief ключевая функция хеширования (функция вычисления имитовставки) */
     mac_function,
   /*! \brief электронная цифровая подпись */
     digital_signature,
   /*! \brief генератор случайных и псевдо-случайных последовательностей */
     random_generator,
   /*! \brief механизм итерационного вычисления сжимающих отображений */
     update_engine
} ak_oid_engine;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Режим и параметры использования криптографического механизма. */
 typedef enum {
   /*! \brief неопределенный режим, может возвращаться в как ошибка */
     undefined_mode,
   /*! \brief собственно криптографический механизм (алгоритм) */
     algorithm,
   /*! \brief данные */
     parameter,
   /*! \brief набор параметров эллиптической кривой в форме Вейерштрасса */
     wcurve_params,
   /*! \brief набор параметров эллиптической кривой в форме Эдвардса */
     ecurve_params,
   /*! \brief набор перестановок */
     kbox_params,
   /*! \brief режим простой замены блочного шифра */
     ecb,
   /*! \brief режим гаммирования для блочного шифра */
     ofb,
   /*! \brief режим гаммирования ГОСТ 28147-89 для блочного шифра */
     ofb_gost,
   /*! \brief режим гаммирования с обратной связью блочного шифра */
     cfb,
   /*! \brief режим ростой замены с зацеплением блочного шифра */
     cbc,
   /*! \brief режим шифрования XTS для блочного шифра */
     xts,
   /*! \brief шифрование с аутентификацией сообщений */
     xts_mac,
   /*! \brief режим гаммирования поточного шифра (сложение по модулю 2) */
     xcrypt,
   /*! \brief гаммирование по модулю \f$ 2^8 \f$ поточного шифра */
     a8
} ak_oid_mode;

/* ----------------------------------------------------------------------------------------------- */
 struct buffer;
/*! \brief Контекст буффера. */
 typedef struct buffer *ak_buffer;

/* ----------------------------------------------------------------------------------------------- */
 struct oid;
/*! \brief Контекст идентификатора объекта. */
 typedef struct oid *ak_oid;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает уровень аудита библиотеки. */
 dll_export int ak_log_get_level( void );
/*! \brief Прямой вывод сообщения аудита. */
 dll_export int ak_log_set_message( const char * );
/*! \brief Явное задание функции аудита. */
 dll_export int ak_log_set_function( ak_function_log * );
#ifdef LIBAKRYPT_HAVE_SYSLOG_H
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
/*! \brief Функция остановки поддержки криптографических механизмов. */
 dll_export int ak_libakrypt_destroy( void );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание дескриптора линейного конгруэнтного генератора. */
 dll_export ak_handle ak_random_new_lcg( void  );
/*! \brief Создание дескриптора генератора, предоставляющего доступ к заданному файлу с данными. */
 dll_export ak_handle ak_random_new_file( const char * );
#ifdef __linux__
/*! \brief Создание дескриптора генератора, предоставляющего доступ к символьному устройству `/dev/random`. */
 dll_export ak_handle ak_random_new_dev_random( void );
/*! \brief Создание дескриптора генератора, предоставляющего доступ к символьному устройству `/dev/urandom`. */
 dll_export ak_handle ak_random_new_dev_urandom( void );
#endif
#ifdef _WIN32
/*! \brief Создание дескриптора системного генератора ОС Windows. */
 dll_export ak_handle ak_random_new_winrtl( void );
#endif
/*! \brief Создание дескриптора генератора по его OID. */
 dll_export ak_handle ak_random_new_oid( ak_oid );

/*! \brief Заполнение заданного массива случайными данными. */
 dll_export int ak_random_ptr( ak_handle, const ak_pointer, const size_t );
/*! \brief Создание буффера заданного размера со случайными данными. */
 dll_export ak_buffer ak_random_buffer( ak_handle, const size_t );
/*! \brief Выработка одного псевдо-случайного байта. */
 dll_export ak_uint8 ak_random_uint8( ak_handle );
/*! \brief Выработка одного псевдо-случайного слова размером 8 байт (64 бита). */
 dll_export ak_uint64 ak_random_uint64( ak_handle );
/*! \brief Инициализация генератора данными, содержащимися в заданной области памяти. */
 dll_export int ak_random_randomize( ak_handle, const ak_pointer, const size_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание буффера заданного размера. */
 dll_export ak_buffer ak_buffer_new_size( const size_t );
/*! \brief Создание буффера с данными. */
 dll_export ak_buffer ak_buffer_new_ptr( const ak_pointer , const size_t , const ak_bool );
/*! \brief Создание буффера с данными, записанными в шестнадцатеричном виде. */
 dll_export ak_buffer ak_buffer_new_hexstr( const char * );
/*! \brief Создание буффера заданной длины с данными, записанными в шестнадцатеричном виде. */
 dll_export ak_buffer ak_buffer_new_hexstr_size( const char * , const size_t , const ak_bool );
/*! \brief Создание буффера, содержащего строку символов, оканчивающуюся нулем. */
 dll_export ak_buffer ak_buffer_new_str( const char * );
/*! \brief Уничтожение буффера. */
 dll_export ak_pointer ak_buffer_delete( ak_pointer );
/*! \brief Пощемение двоичных данных в буффер. */
 dll_export int ak_buffer_set_ptr( ak_buffer , const ak_pointer , const size_t , const ak_bool );
/*! \brief Пощемение в буффер данных, заданных строкой в  шестнадцатеричном представлении. */
 dll_export int ak_buffer_set_hexstr( ak_buffer, const char * );
/*! \brief Помещение строки, оканчивающейся нулем, в буффер. */
 dll_export int ak_buffer_set_str( ak_buffer, const char * );
/*! \brief Получение указателя на данные (как на строку символов). */
 dll_export const char *ak_buffer_get_str( ak_buffer );
/*! \brief Получение указателя на данные. */
 dll_export ak_pointer ak_buffer_get_ptr( ak_buffer );
/*! \brief Получение размера буффера. */
 dll_export const size_t ak_buffer_get_size( ak_buffer );
/*! \brief Получение строки символов с шестнадцатеричным значением буффера. */
 dll_export char *ak_buffer_to_hexstr( const ak_buffer );
/*! \brief Сравнение двух буфферов. */
 dll_export ak_bool ak_buffer_is_equal( const ak_buffer, const ak_buffer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Получение читаемого имени OID. */
 dll_export const char *ak_oid_get_name( ak_oid );
/*! \brief Получение значения OID - последовательности чисел, разделенных точками. */
 dll_export const char *ak_oid_get_id( ak_oid );
/*! \brief Получение криптографического механизма OID. */
 dll_export const ak_oid_engine ak_oid_get_engine( ak_oid );
/*! \brief Получение словесного описания для криптографического механизма OID. */
 dll_export const char *ak_oid_get_engine_str( ak_oid );
/*! \brief Получение режима использования криптографического механизма OID. */
 dll_export const ak_oid_mode ak_oid_get_mode( ak_oid );
/*! \brief Получение общего числа доступных OID библиотеки. */
 dll_export size_t ak_oids_get_count( void );
/*! \brief Получение OID с заданным индексом. */
 dll_export const ak_oid ak_oids_get_oid( const size_t );
/*! \brief Поиск OID по его имени. */
 dll_export const ak_oid ak_oids_find_by_name( const char * );
/*! \brief Поиск OID по его идентификатору (строке цифр, разделенных точками). */
 dll_export const ak_oid ak_oids_find_by_id( const char * );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание строки символов, содержащей значение заданной области памяти. */
 dll_export char *ak_ptr_to_hexstr( const ak_pointer , const size_t , const ak_bool );
/*! \brief Конвертация строки шестнадцатеричных символов в массив данных. */
 dll_export int ak_hexstr_to_ptr( const char *, ak_pointer , const size_t , const ak_bool );
/*! \brief Сравнение двух областей памяти. */
 dll_export ak_bool ak_ptr_is_equal( const ak_pointer, const ak_pointer , const size_t );

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
