/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  libakrypt.h                                                                                    */
/*  Файл содержит перечень экспортируемых интерфейсов библиотеки                                   */
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
/* Обрабатываем вариант сборки библиотеки для работы под Windows (Win32)                           */
#ifdef building_dll
 #define dll_export __declspec (dllexport)
#else
/* ----------------------------------------------------------------------------------------------- */
/* Для остальных операционных систем символ теряет свой смысл ;)                                   */
 #define dll_export
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef _MSC_VER
 #pragma warning (disable : 4996)
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
 #include <sys/types.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_PTHREAD
 #include <pthread.h>
#endif
/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_STDALIGN
 #include <stdalign.h>
#endif
/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_BUILTIN_XOR_SI128
 #include <emmintrin.h>
#endif
/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64
 #include <wmmintrin.h>
#endif
/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_WINDOWS_H
 #include <windows.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef _MSC_VER
 #include <io.h>
 #include <conio.h>
 #include <process.h>
 typedef __int32 ak_int32;
 typedef unsigned __int32 ak_uint32;
 typedef __int64 ak_int64;
 typedef unsigned __int64 ak_uint64;
#endif
#ifdef __MINGW32__
 typedef __int32 ak_int32;
 typedef unsigned __int32 ak_uint32;
 typedef __int64 ak_int64;
 typedef unsigned __int64 ak_uint64;
#endif
#ifdef MSYS
 typedef int32_t ak_int32;
 typedef u_int32_t ak_uint32;
 typedef int64_t ak_int64;
 typedef u_int64_t ak_uint64;
 int snprintf(char *str, size_t size, const char *format, ... );
#endif
#if defined(__unix__) || defined(__APPLE__)
 typedef signed int ak_int32;
 typedef unsigned int ak_uint32;
 typedef signed long long int ak_int64;
 typedef unsigned long long int ak_uint64;
#endif

/* ----------------------------------------------------------------------------------------------- */
 typedef signed char ak_int8;
 typedef unsigned char ak_uint8;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура для обработки 128-ми битных значений. */
 typedef union {
    ak_uint8 b[16];
    ak_uint32 w[4];
    ak_uint64 q[2];
 } ak_uint128;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Определение булева типа, принимающего значения либо истина, либо ложь. */
 typedef enum { ak_false, ak_true } ak_bool;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Указатель на произвольный объект библиотеки. */
 typedef void *ak_pointer;
/*! \brief Дескриптор произвольного объекта библиотеки. */
 typedef ak_int64 ak_handle;
/*! \brief Пользовательская функция аудита. */
 typedef int ( ak_function_log )( const char * );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Результат, говорящий об отсутствии ошибки. */
 #define ak_error_ok                            (0)
/*! \brief Ошибка выделения оперативной памяти. */
 #define ak_error_out_of_memory                (-1)
/*! \brief Ошибка, возникающая при доступе или передаче в качестве аргумента функции null указателя. */
 #define ak_error_null_pointer                 (-2)
/*! \brief Ошибка, возникащая при передаче аргументов функции или выделении памяти нулевой длины. */
 #define ak_error_zero_length                  (-3)
/*! \brief Ошибка, возникающая при обработке данных ошибочной длины. */
 #define ak_error_wrong_length                 (-4)
/*! \brief Использование неопределенного значения. */
 #define ak_error_undefined_value              (-5)
/*! \brief Использование неопределенного указателя на функцию (вызов null указателя). */
 #define ak_error_undefined_function           (-6)
/*! \brief Ошибка переполнения контролируемой переменной */
 #define ak_error_overflow                     (-7)
/*! \brief Попытка доступа к неопределенной опции библиотеки. */
 #define ak_error_wrong_option                 (-8)

/*! \brief Ошибка создания файла. */
 #define ak_error_create_file                 (-10)
/*! \brief Ошибка доступа к файлу (устройству). */
 #define ak_error_access_file                 (-11)
/*! \brief Ошибка открытия файла (устройства). */
 #define ak_error_open_file                   (-12)
/*! \brief Ошибка закрытия файла (устройства). */
 #define ak_error_close_file                  (-13)
/*! \brief Ошибка чтения из файла (устройства). */
 #define ak_error_read_data                   (-14)
/*! \brief Ошибка записи в файл (устройство). */
 #define ak_error_write_data                  (-15)
/*! \brief Ошибка записи в файл - файл существует */
 #define ak_error_file_exists                 (-16)

/*! \brief Ошибка при сравнении двух массивов данных. */
 #define ak_error_not_equal_data              (-20)
/*! \brief Ошибка выполнения библиотеки на неверной архитектуре. */
 #define ak_error_wrong_endian                (-21)
/*! \brief Ошибка чтения из терминала. */
 #define ak_error_terminal                    (-22)

/*! \brief Неверное значение дескриптора объекта. */
 #define ak_error_wrong_handle                (-30)
/*! \brief Ошибка, возникающая в случае неправильного значения размера структуры хранения контекстов. */
 #define ak_error_context_manager_size        (-31)
/*! \brief Ошибка, возникающая при превышении числа возможных элементов структуры хранения контекстов. */
 #define ak_error_context_manager_max_size    (-32)

/*! \brief Неверный тип криптографического механизма. */
 #define ak_error_oid_engine                  (-40)
/*! \brief Неверный режим использования криптографического механизма. */
 #define ak_error_oid_mode                    (-41)
/*! \brief Ошибочное или не определенное имя криптографического механизма. */
 #define ak_error_oid_name                    (-42)
/*! \brief Ошибочный или неопределенный идентификатор криптографического механизма. */
 #define ak_error_oid_id                      (-43)
/*! \brief Ошибочный индекс идентификатора криптографического механизма. */
 #define ak_error_oid_index                   (-44)
/*! \brief Ошибка с обращением к oid. */
 #define ak_error_wrong_oid                   (-45)

/*! \brief Ошибка исчерпания количества возможных использований ключа. */
 #define ak_error_resource_counter            (-50)
/*! \brief Ошибка, возникающая при использовании ключа, значение которого не определено. */
 #define ak_error_key_value                   (-51)
/*! \brief Ошибка, возникающая при зашифровании/расшифровании данных, длина которых не кратна длине блока. */
 #define ak_error_wrong_block_cipher_length   (-52)
/*! \brief Ошибка, возникающая при неверном значении кода целостности ключа. */
 #define ak_error_wrong_key_icode             (-53)
/*! \brief Ошибка, возникающая при недостаточном ресурсе ключа. */
 #define ak_error_low_key_resource            (-54)
/*! \brief Ошибка, возникающая при использовании синхропосылки (инициализационного вектора) неверной длины. */
 #define ak_error_wrong_iv_length             (-55)
/*! \brief Ошибка, возникающая при неправильном использовании функций зашифрования/расшифрования данных. */
 #define ak_error_wrong_block_cipher_function (-56)

/*! \brief Ошибка, возникающая если заданная точка не принадлежит заданной кривой. */
 #define ak_error_curve_point                 (-60)
/*! \brief Ошибка, возникающая когда порядок точки неверен. */
 #define ak_error_curve_point_order           (-61)
/*! \brief Ошибка, возникающая если дискриминант кривой равен нулю (уравнение не задает кривую). */
 #define ak_error_curve_discriminant          (-62)
/*! \brief Ошибка, возникающая когда неверно определены вспомогательные параметры эллиптической кривой. */
 #define ak_error_curve_order_parameters      (-63)
/*! \brief Ошибка, возникающая когда простой модуль кривой задан неверно. */
 #define ak_error_curve_prime_size            (-64)

/*! \brief Ошибка, возникающая при кодировании ASN1 структуры (перевод в DER-кодировку). */
 #define ak_error_wrong_asn1_encode           (-70)
/*! \brief Ошибка, возникающая при декодировании ASN1 структуры (перевод из DER-кодировки в ASN1 структуру). */
 #define ak_error_wrong_asn1_decode           (-71)

/* ----------------------------------------------------------------------------------------------- */
 #define ak_null_string                  ("(null)")

/*! \brief Минимальный уровень аудита */
 #define ak_log_none                            (0)
/*! \brief Стандартный уровень аудита */
 #define ak_log_standard                        (1)
/*! \brief Максимальный уровень аудита */
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
   /*! \brief функция выработки электронной подписи (секретный ключ электронной подписи) */
     sign_function,
   /*! \brief функция проверки электронной подписи (ключ проверки электронной подписи) */
     verify_function,
   /*! \brief генератор случайных и псевдо-случайных последовательностей */
     random_generator,
   /*! \brief механизм итерационного вычисления сжимающих отображений */
     update_engine,
   /*! \brief механизм идентификаторов криптографических алгоритмов */
     oid_engine
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
   /*! \brief режим простой замены блочного шифра (ГОСТ Р 34.13-2015, раздел 5.1) */
     ecb,
   /*! \brief режим гаммирования для блочного шифра (ГОСТ Р 34.13-2015, раздел 5.2) */
     counter,
   /*! \brief режим гаммирования для блочного шифра согласно ГОСТ 28147-89 */
     counter_gost,
   /*! \brief режим гаммирования c обратной связью по выходу (ГОСТ Р 34.13-2015, раздел 5.3) */
     ofb,
   /*! \brief режим простой замены с зацеплением (ГОСТ Р 34.13-2015, раздел 5.4) */
     cbc,
   /*! \brief режим гаммирования c обратной связью по шифртексту (ГОСТ Р 34.13-2015, раздел 5.5) */
     cfb,
   /*! \brief режим шифрования XTS для блочного шифра */
     xts,
   /*! \brief шифрование с аутентификацией сообщений */
     xts_mac,
   /*! \brief режим гаммирования поточного шифра (сложение по модулю 2) */
     xcrypt,
   /*! \brief гаммирование по модулю \f$ 2^8 \f$ поточного шифра */
     a8,
   /*! \brief вычисление электронной подписи */
     signify,
   /*! \brief проверка электронной подписи */
     verify
} ak_oid_mode;

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
/*! \brief Функция возвращает общее количества опций библиотеки. */
 dll_export const size_t ak_libakrypt_options_count( void );
/*! \brief Получение имени опции по ее номеру. */
 dll_export char *ak_libakrypt_get_option_name( const size_t index );
/*! \brief Получение значения опции по ее номеру. */
 dll_export ak_int32 ak_libakrypt_get_option_value( const size_t index );


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает константный указатель NULL-строку с текущей версией библиотеки. */
 dll_export const char *ak_libakrypt_version( void );
/*! \brief Функция инициализации и тестирования криптографических механизмов библиотеки. */
 dll_export int ak_libakrypt_create( ak_function_log * );
/*! \brief Функция остановки поддержки криптографических механизмов. */
 dll_export int ak_libakrypt_destroy( void );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание строки символов, содержащей значение заданной области памяти. */
 dll_export char *ak_ptr_to_hexstr( const ak_pointer , const size_t , const ak_bool );
/*! \brief Преобразование области памяти в символьное представление. */
 dll_export int ak_ptr_to_hexstr_static( const ak_pointer , const size_t , ak_pointer ,
                                                                     const size_t , const ak_bool );
/*! \brief Конвертация строки шестнадцатеричных символов в массив данных. */
 dll_export int ak_hexstr_to_ptr( const char *, ak_pointer , const size_t , const ak_bool );
/*! \brief Сравнение двух областей памяти. */
 dll_export ak_bool ak_ptr_is_equal( const ak_pointer, const ak_pointer , const size_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Чтение пароля из консоли. */
 dll_export int ak_password_read( char *, const size_t );

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

/* ----------------------------------------------------------------------------------------------- */
#define ak_max(x,y) ((x) > (y) ? (x) : (y))
#define ak_min(x,y) ((x) < (y) ? (x) : (y))

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                     libakrypt.h */
/* ----------------------------------------------------------------------------------------------- */
