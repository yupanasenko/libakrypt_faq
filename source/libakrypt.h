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
/*! \brief Структура для обработки 128-ми битных значений                                          */
 typedef union {
    ak_uint8 b[16];
    ak_uint64 q[2];
 } ak_uint128;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Определение булева типа, принимающего значения либо истина, либо ложь                   */
 typedef enum { ak_false, ak_true } ak_bool;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Буффер для хранения данных */
 struct buffer;
/*! \brief Контекст буффера */
 typedef struct buffer *ak_buffer;
/*! \brief OID (Object IDentifier) - уникальный идентификатор криптографического механизма */
 struct oid;
/*! \brief Контекст OID */
 typedef struct oid *ak_oid;
/*! \brief Генератор псевдо-случайных чисел */
 struct random;
/*! \brief Контекст генератора псевдослучайных чисел */
 typedef struct random *ak_random;
/*! \brief Структура для хранения данных бесключевой функции хеширования */
 struct hash;
/*! \brief Контекст бесключевой функции хеширования */
 typedef struct hash *ak_hash;
/*! \brief Структура для итеративного вычисления значений сжимающих отображений */
 struct update;
/*! \brief Контекст структуры итеративного вычисления сжимающих отображений */
 typedef struct update *ak_update;
/*! \brief Дескриптор ключа */
 typedef ak_int64 ak_key;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Указатель на произвольный объект библиотеки */
 typedef void *ak_pointer;
/*! \brief Стандартная для языка С функция выделения памяти                                        */
 typedef ak_pointer ( ak_function_alloc )( size_t );
/*! \brief Стандартная для языка С функция освобождения памяти                                     */
 typedef void ( ak_function_free )( ak_pointer );
/*! \brief Функция, возвращающая NULL после освобождения памяти                                    */
 typedef ak_pointer ( ak_function_free_object )( ak_pointer );
/*! \brief Стандартная для языка С функция перераспределения памяти                                */
 typedef ak_pointer ( ak_function_realloc )( ak_pointer , size_t );
/*! \brief Пользовательская функция аудита                                                         */
 typedef int ( ak_function_log )( const char * );

/* ----------------------------------------------------------------------------------------------- */
 #define ak_error_ok                          (0)
 #define ak_error_out_of_memory              (-1)
 #define ak_error_null_pointer               (-2)
 #define ak_error_zero_length                (-3)
 #define ak_error_wrong_length               (-4)
 #define ak_error_undefined_value            (-5)
 #define ak_error_undefined_function         (-6)
 #define ak_error_create_function            (-7)
 #define ak_error_access_file               (-10)
 #define ak_error_open_file                 (-11)
 #define ak_error_close_file                (-12)
 #define ak_error_find_pointer              (-13)
 #define ak_error_read_data                 (-15)
 #define ak_error_write_data                (-16)
 #define ak_error_oid_engine                (-17)
 #define ak_error_oid_mode                  (-18)
 #define ak_error_oid_name                  (-19)
 #define ak_error_oid_id                    (-20)
 #define ak_error_oid_index                 (-21)
 #define ak_error_not_equal_data            (-22)
 #define ak_error_low_key_resource          (-23)
 #define ak_error_wrong_key_lock            (-24)
 #define ak_error_wrong_key_unlock          (-25)
 #define ak_error_wrong_key_icode           (-26)
 #define ak_error_wcurve_prime_size         (-27)
 #define ak_error_wcurve_discriminant       (-28)
 #define ak_error_wcurve_point              (-29)
 #define ak_error_wcurve_point_order        (-30)
 #define ak_error_context_manager_max_size  (-31)
 #define ak_error_block_cipher_length       (-32)

 #define ak_null_string                ("(null)")

 #define ak_log_none                          (0)
 #define ak_log_standard                      (1)
 #define ak_log_maximum                       (2)

 #define ak_key_wrong                        (-1)

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает уровень аудита библиотеки */
 dll_export int ak_log_get_level( void );
/*! \brief Прямой вывод сообщения аудита */
 dll_export int ak_log_set_message( const char * );
/*! \brief Явное задание функции аудита */
 dll_export int ak_log_set_function( ak_function_log * );
#ifdef __linux__
 /*! \brief Функиция вывода сообщения об ошибке с помощью демона операционной системы */
 int ak_function_log_syslog( const char * );
#endif
/*! \brief Функция вывода сообщения об ошибке в стандартный канал вывода ошибок */
 dll_export int ak_function_log_stderr( const char * );
/*! \brief Вывод сообщений о возникшей в процессе выполнения ошибке */
 dll_export int ak_error_message( const int, const char *, const char * );
/*! \brief Функция устанавливает значение переменной, хранящей ошибку выполнения программы */
 dll_export int ak_error_set_value( const int );
/*! \brief Функция возвращает код последней ошибки выполнения программы */
 dll_export int ak_error_get_value( void );
/*! \brief Функция возвращает константный указатель NULL-строку с текущей версией библиотеки */
 dll_export const char *ak_libakrypt_version( void );
/*! \brief Функция инициализации и тестирования криптографических механизмов библиотеки */
 dll_export int ak_libakrypt_create( ak_function_log * );
/*! \brief Функция останавки поддержки криптографических механизмов */
 dll_export int ak_libakrypt_destroy( void );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание буффера */
 dll_export ak_buffer ak_buffer_new( void );
/*! \brief Создание буффера заданного размера */
 dll_export ak_buffer ak_buffer_new_size( const size_t );
/*! \brief Создание буффера с данными */
 dll_export ak_buffer ak_buffer_new_ptr( const ak_pointer , const size_t , const ak_bool );
/*! \brief Создание буффера с данными, записанными в шестнадцатеричном виде */
 dll_export ak_buffer ak_buffer_new_hexstr( const char * );
/*! \brief Создание буффера заданной длины с данными, записанными в шестнадцатеричном виде */
 dll_export ak_buffer ak_buffer_new_hexstr_str( const char * , const size_t , const ak_bool );
/*! \brief Создание буффера, содержащего строку символов, оканчивающуюся нулем */
 dll_export ak_buffer ak_buffer_new_str( const char * );
/*! \brief Функция создает буффер заданный длины со случайными значениями */
 dll_export ak_buffer ak_buffer_new_random( ak_random, const size_t );
/*! \brief Зачистка данных, хранящихся в буффере */
 dll_export int ak_buffer_wipe( ak_buffer, ak_random );
/*! \brief Уничтожение буффера */
 dll_export ak_pointer ak_buffer_delete( ak_pointer );
/*! \brief Пощемение двоичных данных в буффер */
 dll_export int ak_buffer_set_ptr( ak_buffer , const ak_pointer , const size_t , const ak_bool );
/*! \brief Пощемение в буффер данных, заданных строкой в  шестнадцатеричном представлении */
 dll_export int ak_buffer_set_hexstr( ak_buffer, const char * );
/*! \brief Помещение строки, оканчивающейся нулем, в буффер */
 dll_export int ak_buffer_set_str( ak_buffer, const char * );
/*! \brief Заполнение буффера случайными данными */
 dll_export int ak_buffer_set_random( ak_buffer , ak_random );
/*! \brief Получение указателя на данные (как на строку символов) */
 dll_export const char *ak_buffer_get_str( ak_buffer );
/*! \brief Получение указателя на данные */
 dll_export ak_pointer ak_buffer_get_ptr( ak_buffer );
/*! \brief Получение размера буффера */
 dll_export const size_t ak_buffer_get_size( ak_buffer );
/*! \brief Получение строки символов с шестнадцатеричным значением буффера */
 dll_export char *ak_buffer_to_hexstr( const ak_buffer );
/*! \brief Сравнение двух буфферов */
 dll_export int ak_buffer_is_equal( const ak_buffer, const ak_buffer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тип криптографического механизма                                                        */
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
   /*! \brief ключевая функция хеширования */
     mac_function,
   /*! \brief электронная цифровая подпись */
     digital_signature,
   /*! \brief ДСЧ (генератор псевдослучайных последовательностей) */
     random_generator
 } ak_oid_engine;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Режим и параметры использования криптографического механизма                            */
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
   /*! \brief режим гаммирования поточного шифра */
     xcrypt,
   /*! \brief гаммирование по модулю \f$ 2^8 \f$ поточного шифра */
     a8
 } ak_oid_mode;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Получение читаемого имени OID */
 dll_export const char *ak_oid_get_name( ak_oid );
/*! \brief Получение значения OID - последовательности чисел, разделенных точками */
 dll_export const char *ak_oid_get_id( ak_oid );
/*! \brief Получение криптографического механизма OID */
 dll_export const ak_oid_engine ak_oid_get_engine( ak_oid );
/*! \brief Получение режима использования криптографического механизма OID */
 dll_export const ak_oid_mode ak_oid_get_mode( ak_oid );
/*! \brief Получение общего числа доступных OID библиотеки */
 dll_export size_t ak_oids_get_count( void );
 /*! \brief Получение OID с заданным индексом */
 dll_export const ak_oid ak_oids_get_oid( const size_t );
 /*! \brief Поиск OID по его имени */
 dll_export const ak_oid ak_oids_find_by_name( const char * );
 /*! \brief Поиск OID по его идентификатору (строке цифр, разделенных точками) */
 dll_export const ak_oid ak_oids_find_by_id( const char * );
/*! \brief Функция добавляет в массив OID'ов библиотеки новые таблицы замен для ГОСТ 28147-89 */
 dll_export int ak_oids_add_gost28147_tables( const char *, const char *, const ak_uint8[8][16] );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание контекста алгоритма хеширования по заданному OID */
 dll_export ak_hash ak_hash_new_oid( ak_oid );
/*! \brief Функция создает контекст алгоритма бесключевого хеширования ГОСТ Р 34.11-94 */
 dll_export ak_hash ak_hash_new_gosthash94( ak_oid );
/*! \brief Функция создает контекст алгоритма бесключевого хеширования ГОСТ Р 34.11-2012 */
 dll_export ak_hash ak_hash_new_streebog256( void );
/*! \brief Функция создает контекст алгоритма бесключевого хеширования ГОСТ Р 34.11-2012 */
 dll_export ak_hash ak_hash_new_streebog512( void );
/*! \brief Получение длины хешкода алгоритма хеширования (в байтах) */
 dll_export size_t ak_hash_get_code_size( ak_hash );
/*! \brief Получение длины блока обрабатываемых данных (в байтах) */
 dll_export size_t ak_hash_get_block_size( ak_hash );
/*! \brief Получение OID алгоритма хеширования */
 dll_export ak_oid ak_hash_get_oid( ak_hash );
/*! \brief Начальная инициализация и очистка контекста функции хеширования */
 dll_export int ak_hash_clean( ak_hash );
/*! \brief Вычисление хешкода для заданной области памяти известной длины */
 dll_export ak_buffer ak_hash_data( ak_hash, const ak_pointer , const size_t , ak_pointer );
/*! \brief Вычисление хешкода для заданного файла */
 dll_export ak_buffer ak_hash_file( ak_hash, const char * , ak_pointer );
/*! \brief Обновление текущего состояния контекста функции хеширования */
 dll_export int ak_hash_update( ak_hash , const ak_pointer , const size_t );
/*! \brief Завершение хеширования и закрытие контекста функции хеширования */
 dll_export ak_buffer ak_hash_finalize( ak_hash , const ak_pointer , const size_t , ak_pointer );
/*! \brief Удаление контекста хеширования */
 dll_export ak_pointer ak_hash_delete( ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание линейного конгруэнтного генератора псевдо-случайных чисел */
 dll_export ak_random ak_random_new_lcg( void );
/*! \brief Cоздание генератора, считывающего случайные значения из заданного файла */
 dll_export ak_random ak_random_new_file( const char *filename );
/*! \brief Инициализация генератора случайным числом */
 dll_export int ak_random_randomize( ak_random );
/*! \brief Инициализация генератора заданным числом */
 dll_export int ak_random_randomize_uint64( ak_random, const ak_uint64 );
/*! \brief Инициализация генератора данными, содержащимися в заданной области памяти */
 dll_export int ak_random_randomize_ptr( ak_random, const ak_pointer, const size_t );
/*! \brief Выработка псевдо случайного байта */
 dll_export ak_uint8 ak_random_uint8( ak_random );
/*! \brief Выработка 64-х битного псевдо случайного числа (восемь байт) */
 dll_export ak_uint64 ak_random_uint64( ak_random );
/*! \brief Заполнение заданного массива псевдо случайными данными */
 dll_export int ak_random_ptr( ak_random, const ak_pointer, const size_t );
/*! \brief Уничтожение генератора псевдо-случайных чисел */
 dll_export ak_pointer ak_random_delete( ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
 dll_export ak_update ak_update_new_hash( ak_hash );
 dll_export ak_pointer ak_update_delete( ak_pointer );
 dll_export size_t ak_update_get_code_size( ak_update );
 dll_export int ak_update_clean( ak_update );
 dll_export int ak_update_update( ak_update , const ak_pointer , const size_t );
 dll_export ak_buffer ak_update_finalize( ak_update , const ak_pointer , const size_t , ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание строки символов, содержащей значение заданной области памяти */
 dll_export char *ak_ptr_to_hexstr( const ak_pointer , const size_t , const ak_bool );
/*! \brief Конвертация строки шестнадцатеричных символов в массив данных */
 dll_export int ak_hexstr_to_ptr( const char *, ak_pointer , const size_t , const ak_bool );

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
