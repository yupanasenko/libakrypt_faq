/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*  Copyright (c) 2019 by Diffractee                                                               */
/*                                                                                                 */
/*  Файл libakrypt.h                                                                               */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __LIBAKRYPT_H__
#define    __LIBAKRYPT_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-base.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_TESTS_GMP
 #define LIBAKRYPT_HAVE_GMP_H
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Попытка доступа к неопределенной опции библиотеки. */
 #define ak_error_wrong_option                (-100)
/*! \brief Ошибка использования неправильного (неожидаемого) значения. */
 #define ak_error_invalid_value               (-101)

/*! \brief Неверный тип криптографического механизма. */
 #define ak_error_oid_engine                  (-110)
/*! \brief Неверный режим использования криптографического механизма. */
 #define ak_error_oid_mode                    (-111)
/*! \brief Ошибочное или не определенное имя криптографического механизма. */
 #define ak_error_oid_name                    (-112)
/*! \brief Ошибочный или неопределенный идентификатор криптографического механизма. */
 #define ak_error_oid_id                      (-113)
/*! \brief Ошибочный индекс идентификатора криптографического механизма. */
 #define ak_error_oid_index                   (-114)
/*! \brief Ошибка с обращением к oid. */
 #define ak_error_wrong_oid                   (-115)

/*! \brief Ошибка, возникающая когда параметры кривой не соответствуют алгоритму, в котором они используются. */
 #define ak_error_curve_not_supported         (-120)
/*! \brief Ошибка, возникающая если точка не принадлежит заданной кривой. */
 #define ak_error_curve_point                 (-121)
/*! \brief Ошибка, возникающая когда порядок точки неверен. */
 #define ak_error_curve_point_order           (-122)
/*! \brief Ошибка, возникающая если дискриминант кривой равен нулю (уравнение не задает кривую). */
 #define ak_error_curve_discriminant          (-123)
/*! \brief Ошибка, возникающая когда неверно определены вспомогательные параметры эллиптической кривой. */
 #define ak_error_curve_order_parameters      (-124)
/*! \brief Ошибка, возникающая когда простой модуль кривой задан неверно. */
 #define ak_error_curve_prime_modulo          (-125)

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup test-options Инициализация и настройка параметров библиотеки
 @{ */
/*! \brief Функция инициализации библиотеки. */
 dll_export int ak_libakrypt_create( ak_function_log * );
/*! \brief Функция завершает работу с библиотекой. */
 int ak_libakrypt_destroy( void );
/*! \brief Функция выполняет динамическое тестирование работоспособности криптографических преобразований. */
 dll_export bool_t ak_libakrypt_dynamic_control_test( void );
/*! \brief Функция тестирования корректности реализации операций умножения в полях характеристики два. */
 dll_export bool_t ak_libakrypt_test_gfn_multiplication( void );
 /*! \brief Функция тестирует все определяемые библиотекой параметры эллиптических кривых,
    заданных в короткой форме Вейерштрасса. */
 dll_export bool_t ak_libakrypt_test_wcurves( void );
/*! \brief Функция проверяет корректность реализации асимметричных криптографических алгоритмов. */
 dll_export bool_t ak_libakrypt_test_asymmetric_functions( void );
/*! \brief Проверка корректной работы функции хеширования Стрибог-256 */
 dll_export bool_t ak_libakrypt_test_streebog256( void );
/*! \brief Проверка корректной работы функции хеширования Стрибог-512 */
 dll_export bool_t ak_libakrypt_test_streebog512( void );
/*! \brief Функция проверяет корректность реализации алгоритмов хэширования. */
 dll_export bool_t ak_libakrypt_test_hash_functions( void );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает номер версии бибилиотеки libakrypt. */
 dll_export const char *ak_libakrypt_version( void );
/*! \brief Функция возвращает общее количества опций библиотеки. */
 dll_export size_t ak_libakrypt_options_count( void );
/*! \brief Функция возвращает имя функции по ее индексу. */
 dll_export char *ak_libakrypt_get_option_name( const size_t );
/*! \brief Функция возвращает значение опции по ее имени. */
 dll_export ak_int64 ak_libakrypt_get_option_by_name( const char * );
/*! \brief Функция возвращает значение опции по ее индексу. */
 dll_export ak_int64 ak_libakrypt_get_option_by_index( const size_t );
/*! \brief Функция устанавливает значение заданной опции. */
 dll_export int ak_libakrypt_set_option( const char * , const ak_int64 );
/*! \brief Функция считывает значения опций библиотеки из файла. */
 dll_export bool_t ak_libakrypt_load_options( void );
/*! \brief Функция выводит текущие значения всех опций библиотеки. */
 dll_export void ak_libakrypt_log_options( void );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция устанавливает режим совместимости криптографических преобразований с библиотекой openssl. */
 dll_export int ak_libakrypt_set_openssl_compability( bool_t );
/*! \brief Функция получает домашний каталог библиотеки. */
 dll_export int ak_libakrypt_get_home_path( char * , const size_t );
/*! \brief Функция создает полное имя файла в домашем каталоге библиотеки. */
 dll_export int ak_libakrypt_create_home_filename( char * , const size_t , char * , const int );
/*! \brief Функция выводит в заданный файл параметры эллиптической кривой. */
 int ak_libakrypt_print_curve( FILE * , const char * );
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup oid Идентификаторы криптографических механизмов
 @{ */
/*! \brief Указатель на идентификатор криптографического механизма */
 typedef struct oid *ak_oid;
/*! \brief Функция, возвращающая код ошибки после инициализации объекта (конструктор). */
 typedef int ( ak_function_create_object ) ( ak_pointer );
/*! \brief Функция, возвращающая код ошибки после разрушения объекта (деструктор). */
 typedef int ( ak_function_destroy_object ) ( ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура, контролирующая функционирование криптографических объектов библиотеки. */
/*! \details Структура представляет из себя описатель класса, позволяющий создавать и уничтожать
 объекты данного класса, а также вызывать базовые функции чтения и сохранения объектов.            */
/* ----------------------------------------------------------------------------------------------- */
 typedef struct object {
 /*! \brief Размер области памяти для объекта */
  size_t size;
 /*! \brief Конструктор объекта. */
  ak_function_create_object *create;
 /*! \brief Деструктор объекта. */
  ak_function_destroy_object *destroy;
} *ak_object;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тип криптографического механизма. */
 typedef enum {
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
   /*! \brief семейство ключевых функций хеширования HMAC */
     hmac_function,
   /*! \brief семейство функций выработки имитовставки согласно ГОСТ Р 34.13-2015. */
     cmac_function,
   /*! \brief семейство функций выработки имитовставки MGM. */
     mgm_function,
   /*! \brief класс всех ключевых функций хеширования (функций вычисления имитовставки) */
     mac_function,
   /*! \brief функция выработки электронной подписи (секретный ключ электронной подписи) */
     sign_function,
   /*! \brief функция проверки электронной подписи (ключ проверки электронной подписи) */
     verify_function,
   /*! \brief генератор случайных и псевдо-случайных последовательностей */
     random_generator,
   /*! \brief механизм идентификаторов криптографических алгоритмов */
     oid_engine,
   /*! \brief неопределенный механизм, может возвращаться как ошибка */
     undefined_engine
} oid_engines_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Режим и параметры использования криптографического механизма. */
 typedef enum {
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
   /*! \brief режим аутентифицирующего шифрования, согласно Р 1323565.1.028-2019 */
     mgm,
   /*! \brief режим аутентифицирующего шифрования */
     xtsmac,
   /*! \brief режим гаммирования поточного шифра (сложение по модулю 2) */
     xcrypt,
   /*! \brief гаммирование по модулю \f$ 2^8 \f$ поточного шифра */
     a8,
   /*! \brief описатель для типов данных, помещаемых в asn1 дерево */
     descriptor,
   /*! \brief неопределенный режим, может возвращаться как ошибка */
     undefined_mode
} oid_modes_t;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс для хранения идентификаторов объектов (криптографических механизмов) и их данных. */
/*! OID (Object IDentifier) это уникальная последовательность чисел, разделенных точками.
    OID'ы могут быть присвоены любому криптографическому механизму (алгоритму,
    схеме, протоколу), а также произвольным параметрам этих механизмов.
    Использование OID'в позволяет однозначно определять тип криптографического механизма или
    значения его параметров на этапе выполнения программы, а также
    однозначно связывать данные (как правило ключевые) с алгоритмами, в которых эти данные
    используются.                                                                                  */
/* ----------------------------------------------------------------------------------------------- */
 typedef struct oid {
  /*! \brief Тип криптографического механизма. */
   oid_engines_t engine;
  /*! \brief Режим применения криптографического механизма. */
   oid_modes_t mode;
  /*! \brief Перечень идентификаторов криптографического механизма. */
   const char **id;
  /*! \brief Перечень доступных имен криптографического механизма. */
   const char **name;
  /*! \brief Указатель на данные. */
   ak_pointer data;
  /*! \brief Структура, контролирующая поведение объекта */
   struct object func;
} *ak_oid;

/* ----------------------------------------------------------------------------------------------- */
 #define ak_object_undefined { 0, NULL, NULL }
 #define ak_oid_undefined { undefined_engine, undefined_mode, NULL, NULL, NULL, ak_object_undefined }

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Получение человекочитаемого имени для заданного типа криптографического механизма. */
 dll_export const char *ak_libakrypt_get_engine_name( const oid_engines_t );
/*! \brief Получение человекочитаемого имени режима или параметров криптографического механизма. */
 dll_export const char *ak_libakrypt_get_mode_name( const oid_modes_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Создание объекта в оперативной памяти (куче) */
 dll_export ak_pointer ak_oid_new_object( ak_oid );
/*! \brief Удаление объекта из кучи */
 dll_export ak_pointer ak_oid_delete_object( ak_oid , ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает количество идентификаторов библиотеки. */
 dll_export size_t ak_libakrypt_oids_count( void );
/*! \brief Получение OID по его внутреннему индексу. */
 dll_export ak_oid ak_oid_find_by_index( const size_t );
/*! \brief Поиск OID его имени. */
 dll_export ak_oid ak_oid_find_by_name( const char * );
/*! \brief Поиск OID по его идентификатору (строке цифр, разделенных точками). */
 dll_export ak_oid ak_oid_find_by_id( const char * );
/*! \brief Поиск OID по его имени или идентификатору. */
 dll_export ak_oid ak_oid_find_by_ni( const char * );
/*! \brief Поиск OID по указателю на даные */
 dll_export ak_oid ak_oid_find_by_data( ak_const_pointer  );
/*! \brief Поиск OID по типу криптографического механизма. */
 dll_export ak_oid ak_oid_find_by_engine( const oid_engines_t );
/*! \brief Продолжение поиска OID по типу криптографического механизма. */
 dll_export ak_oid ak_oid_findnext_by_engine( const ak_oid, const oid_engines_t );
/*! \brief Проверка соответствия заданного адреса корректному oid. */
 dll_export bool_t ak_oid_check( const ak_oid );
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup random Генераторы псевдо-случайных чисел
 @{ */
/*! \brief Указатель на класс генератора псевдо-случайных чисел. */
 typedef struct random *ak_random;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция, принимающая в качестве аргумента указатель на структуру struct random. */
 typedef int ( ak_function_random )( ak_random );
/*! \brief Функция обработки данных заданного размера. */
 typedef int ( ak_function_random_ptr_const )( ak_random , const ak_pointer, const ssize_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс, реализующий произвольный генератор псевдо-случайных чисел.                       */
/* ----------------------------------------------------------------------------------------------- */
 struct random {
  /*! \brief OID генератора псевдо-случайных чисел. */
   ak_oid oid;
  /*! \brief Указатель на функцию выработки следующего внутреннего состояния */
   ak_function_random *next;
  /*! \brief Указатель на функцию инициализации генератора заданным массивом значений */
   ak_function_random_ptr_const *randomize_ptr;
  /*! \brief Указатель на функцию выработки последователности псевдо-случайных байт */
   ak_function_random_ptr_const *random;
  /*! \brief Указатель на функцию освобождения внутреннего состояния */
   ak_function_random *free;
  /*! \brief Объединение, определяющее внутренние данные генератора */
   union {
     /*! \brief Внутреннее состояние линейного конгруэнтного генератора */
       ak_uint64 val;
     /*! \brief Внутреннее состояние xorshift32 генератора */
       ak_uint32 value;
     /*! \brief Файловый дескриптор */
       int fd;
    #ifdef AK_HAVE_WINDOWS_H
     /*! \brief Дескриптор крипто-провайдера */
      HCRYPTPROV handle;
    #endif
     /*! \brief Указатель на произвольную структуру данных. */
       ak_pointer ctx;
   } data;
 };

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация контекста линейного конгруэнтного генератора псевдо-случайных чисел. */
 dll_export int ak_random_create_lcg( ak_random );
 /*! \brief Инициализация контекста генератора, считывающего случайные значения из заданного файла. */
 dll_export int ak_random_create_file( ak_random , const char * );
#if defined(__unix__) || defined(__APPLE__)
/*! \brief Инициализация контекста генератора, считывающего случайные значения из /dev/random. */
 dll_export int ak_random_create_random( ak_random );
/*! \brief Инициализация контекста генератора, считывающего случайные значения из /dev/urandom. */
 dll_export int ak_random_create_urandom( ak_random );
#endif
#ifdef _WIN32
/*! \brief Инициализация контекста, реализующего интерфейс доступа к генератору псевдо-случайных чисел, предоставляемому ОС Windows. */
 dll_export int ak_random_create_winrtl( ak_random );
#endif
/*! \brief Инициализация контекста генератора по заданному OID алгоритма генерации псевдо-случайных чисел. */
 dll_export int ak_random_create_oid( ak_random, ak_oid );
/*! \brief Установка внутреннего состояния генератора псевдо-случайных чисел. */
 dll_export int ak_random_randomize( ak_random , const ak_pointer , const ssize_t );
/*! \brief Выработка псевдо-случайных данных. */
 dll_export int ak_random_ptr( ak_random , const ak_pointer , const ssize_t );
/*! \brief Некриптографическая функция генерации случайного 64-х битного целого числа. */
 dll_export ak_uint64 ak_random_value( void );
/*! \brief Уничтожение данных, хранящихся в полях структуры struct random. */
 int ak_random_destroy( ak_random );
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup mpzn Арифметика больших чисел
 @{ */
#ifdef LIBAKRYPT_HAVE_GMP_H
 #include <gmp.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 #define ak_mpzn256_size     (4)
 #define ak_mpzn512_size     (8)
 #define ak_mpznmax_size    (18)

 #define ak_mpzn256_zero  { 0, 0, 0, 0 }
 #define ak_mpzn256_one   { 1, 0, 0, 0 }
 #define ak_mpzn512_zero  { 0, 0, 0, 0, 0, 0, 0, 0 }
 #define ak_mpzn512_one   { 1, 0, 0, 0, 0, 0, 0, 0 }
 #define ak_mpznmax_zero  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
 #define ak_mpznmax_one   { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Элемент кольца вычетов по модулю \f$2^{256}\f$. */
 typedef ak_uint64 ak_mpzn256[ ak_mpzn256_size ];
/*! \brief Элемент кольца вычетов по модулю \f$2^{512}\f$. */
 typedef ak_uint64 ak_mpzn512[ ak_mpzn512_size ];
/*! \brief Тип данных для хранения максимально возможного большого числа. */
 typedef ak_uint64 ak_mpznmax[ ak_mpznmax_size ];

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Присвоение вычету другого вычета. */
 dll_export void ak_mpzn_set( ak_uint64 *, ak_uint64 * , const size_t );
/*! \brief Присвоение вычету беззнакового целого значения. */
 dll_export void ak_mpzn_set_ui( ak_uint64 *, const size_t , const ak_uint64 );
/*! \brief Присвоение вычету случайного значения. */
 dll_export int ak_mpzn_set_random( ak_uint64 *, const size_t , ak_random );
/*! \brief Присвоение вычету случайного значения по фиксированному модулю. */
 dll_export int ak_mpzn_set_random_modulo( ak_uint64 *, ak_uint64 *, const size_t , ak_random );
/*! \brief Присвоение вычету значения, записанного строкой шестнадцатеричных символов. */
 dll_export int ak_mpzn_set_hexstr( ak_uint64 *, const size_t , const char * );
/*! \brief Преобразование вычета в строку шестнадцатеричных символов. */
 dll_export const char *ak_mpzn_to_hexstr( ak_uint64 *, const size_t );
/*! \brief Преобразование вычета в строку шестнадцатеричных символов с выделением памяти. */
 dll_export char *ak_mpzn_to_hexstr_alloc( ak_uint64 *, const size_t );
/*! \brief Сериализация вычета в последовательность октетов. */
 dll_export int ak_mpzn_to_little_endian( ak_uint64 * , const size_t ,
                                                             ak_pointer , const size_t , bool_t );
/*! \brief Присвоение вычету сериализованного значения. */
 dll_export int ak_mpzn_set_little_endian( ak_uint64 * , const size_t ,
                                                       const ak_pointer , const size_t , bool_t );
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Сложение двух вычетов */
 dll_export ak_uint64 ak_mpzn_add( ak_uint64 *, ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Вычитание двух вычетов */
 dll_export ak_uint64 ak_mpzn_sub( ak_uint64 *, ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Сравнение двух вычетов */
 dll_export int ak_mpzn_cmp( ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Сравнение вычета с беззнаковым целым числом (типа ak_uint64) */
 dll_export bool_t ak_mpzn_cmp_ui( ak_uint64 *, const size_t , const ak_uint64 );
/*! \brief Умножение вычета на беззнаковое целое */
 dll_export ak_uint64 ak_mpzn_mul_ui( ak_uint64 *, ak_uint64 *, const size_t, const ak_uint64 );
/*! \brief Умножение двух вычетов как целых чисел */
 dll_export void ak_mpzn_mul( ak_uint64 *, ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Вычисление остатка от деления одного вычета на другой */
 dll_export void ak_mpzn_rem( ak_uint64 *, ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Вычисление остатка от деления вычета на одноразрядное число */
 dll_export ak_uint32 ak_mpzn_rem_uint32( ak_uint64 *, const size_t , ak_uint32 );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Сложение двух вычетов в представлении Монтгомери. */
 dll_export void ak_mpzn_add_montgomery( ak_uint64 *, ak_uint64 *,
                                                         ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Удвоение на двойку в представлении Монтгомери. */
 dll_export void ak_mpzn_lshift_montgomery( ak_uint64 *, ak_uint64 *, ak_uint64 *, const size_t );
/*! \brief Умножение двух вычетов в представлении Монтгомери. */
 dll_export void ak_mpzn_mul_montgomery( ak_uint64 *, ak_uint64 *, ak_uint64 *,
                                                           ak_uint64 *, ak_uint64, const size_t );
/*! \brief Модульное возведение в степень в представлении Монтгомери. */
 dll_export void ak_mpzn_modpow_montgomery( ak_uint64 *, ak_uint64 *, ak_uint64 *,
                                                           ak_uint64 *, ak_uint64, const size_t );
/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_GMP_H
/*! \brief Преобразование ak_mpznxxx в mpz_t. */
 dll_export void ak_mpzn_to_mpz( const ak_uint64 *, const size_t , mpz_t );
/*! \brief Преобразование mpz_t в ak_mpznxxx. */
 dll_export void ak_mpz_to_mpzn( const mpz_t , ak_uint64 *, const size_t );
#endif
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup curves Эллиптические кривые
 @{ */
 struct wcurve;
/*! \brief Контекст эллиптической кривой, заданной в короткой форме Вейерштрасса. */
 typedef struct wcurve *ak_wcurve;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс, реализующий точку эллиптической кривой.

    Класс представляет собой точку \f$ P \f$ эллиптической кривой, заданной в короткой форме Вейерштрасса,
    в проективных координатах, т.е. точка представляется в виде вектора \f$ P=(x:y:z) \f$,
    удовлетворяющего сравнению \f$ y^2z \equiv x^3 + axz^2 + bz^3 \pmod{p} \f$.
    В дальнейшем, при проведении вычислений, для координат точки используется
    представление Монтгомери.                                                                      */
/* ----------------------------------------------------------------------------------------------- */
 struct wpoint
{
/*! \brief x-координата точки эллиптической кривой */
 ak_uint64 x[ak_mpzn512_size];
/*! \brief y-координата точки эллиптической кривой */
 ak_uint64 y[ak_mpzn512_size];
/*! \brief z-координата точки эллиптической кривой */
 ak_uint64 z[ak_mpzn512_size];
};
/*! \brief Контекст точки эллиптической кривой в короткой форме Вейерштрасса */
 typedef struct wpoint *ak_wpoint;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация и присвоение контексту значения образующей точки эллиптической кривой. */
 dll_export int ak_wpoint_set( ak_wpoint, ak_wcurve );
/*! \brief Инициализация и присвоение контексту значения бесконечно удаленной точки эллиптической кривой. */
 dll_export int ak_wpoint_set_as_unit( ak_wpoint , ak_wcurve );
/*! \brief Инициализация и присвоение контексту значения заданной точки эллиптической кривой. */
 dll_export int ak_wpoint_set_wpoint( ak_wpoint , ak_wpoint , ak_wcurve );

/*! \brief Проверка принадлежности точки заданной кривой. */
 dll_export bool_t ak_wpoint_is_ok( ak_wpoint , ak_wcurve );
/*! \brief Проверка порядка заданной точки. */
 dll_export bool_t ak_wpoint_check_order( ak_wpoint , ak_wcurve );

/*! \brief Удвоение точки эллиптической кривой, заданной в короткой форме Вейерштрасса. */
 dll_export void ak_wpoint_double( ak_wpoint , ak_wcurve );
/*! \brief Прибавление к одной точке эллиптической кривой значения другой точки. */
 dll_export void ak_wpoint_add( ak_wpoint , ak_wpoint , ak_wcurve );
/*! \brief Приведение проективной точки к аффинному виду. */
 dll_export void ak_wpoint_reduce( ak_wpoint , ak_wcurve );
/*! \brief Вычисление кратной точки эллиптической кривой. */
 dll_export void ak_wpoint_pow( ak_wpoint , ak_wpoint , ak_uint64 *, size_t , ak_wcurve );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс, реализующий эллиптическую кривую, заданную в короткой форме Вейерштрасса

    Класс определяет эллиптическую кривую, заданную сравнением
    \f$ y^2 \equiv x^3 + ax + b \pmod{p} \f$, а также образующую точку \f$P=(x_P, y_P)\f$
    на этой кривой с заданным порядком \f$ q \f$.

    Порядок \f$ m \f$ всей группы точек эллиптической кривой может быть определен
    из равенства \f$ m = dq \f$, где величину \f$ d \f$ называют кофактором.

    Параметры \f$ n, n_q, r_2\f$ вводятся для оптимизации вычислений. Определим \f$ r = 2^{256}\f$
    или \f$ r=2^{512}\f$, тогда \f$ n \equiv n_0 \pmod{2^{64}}\f$,
    где \f$ n_0 \equiv -p^{-1} \pmod{r}\f$.

    Величина \f$ r_2 \f$ удовлетворяет сравнению \f$ r_2 \equiv r^2 \pmod{p}\f$.                   */
/* ----------------------------------------------------------------------------------------------- */
 struct wcurve
{
 /*! \brief Размер параметров эллиптической кривой, исчисляемый количеством 64-х битных блоков. */
  ak_uint32 size;
 /*! \brief Кофактор эллиптической кривой - делитель порядка группы точек. */
  ak_uint32 cofactor;
 /*! \brief Коэффициент \f$ a \f$ эллиптической кривой (в представлении Монтгомери) */
  ak_uint64 a[ak_mpzn512_size];
 /*! \brief Коэффициент \f$ b \f$ эллиптической кривой (в представлении Монтгомери). */
  ak_uint64 b[ak_mpzn512_size];
 /*! \brief Модуль \f$ p \f$ эллиптической кривой. */
  ak_uint64 p[ak_mpzn512_size];
 /*! \brief Величина \f$ r^2\f$, взятая по модулю \f$ p \f$ и используемая в арифметике Монтгомери. */
  ak_uint64 r2[ak_mpzn512_size];
 /*! \brief Порядок \f$ q \f$ подгруппы, порождаемой образующей точкой \f$ P \f$. */
  ak_uint64 q[ak_mpzn512_size];
 /*! \brief Величина \f$ r^2\f$, взятая по модулю \f$ q \f$ и используемая в арифметике Монтгомери. */
  ak_uint64 r2q[ak_mpzn512_size];
 /*! \brief Точка \f$ P \f$ эллиптической кривой, порождающая подгруппу порядка \f$ q \f$. */
  struct wpoint point;
 /*! \brief Константа \f$ n \f$, используемая в арифметике Монтгомери по модулю \f$ p \f$. */
  ak_uint64 n;
 /*! \brief Константа \f$ n_q \f$, используемая в арифметике Монтгомери по модулю \f$ q\f$. */
  ak_uint64 nq;
 /*! \brief Строка, содержащая символьную запись модуля \f$ p \f$.
     \details Используется для проверки корректного хранения параметров кривой в памяти. */
  const char *pchar;
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Вычисление дискриминанта эллиптической кривой, заданной в короткой форме Вейерштрасса. */
 dll_export void ak_mpzn_set_wcurve_discriminant( ak_uint64 *, ak_wcurve );
/*! \brief Проверка корректности дискриминанта эллиптической кривой, заданной в форме Вейерштрасса. */
 dll_export int ak_wcurve_discriminant_is_ok( ak_wcurve );
/*! \brief Проверка корректности параметров, необходимых для вычисления по модулю q. */
 dll_export int ak_wcurve_check_order_parameters( ak_wcurve );
/*! \brief Проверка набора параметров эллиптической кривой, заданной в форме Вейерштрасса. */
 dll_export int ak_wcurve_is_ok( ak_wcurve );

/* ----------------------------------------------------------------------------------------------- */
/*                         параметры 256-ти битных эллиптических кривых                            */
/* ----------------------------------------------------------------------------------------------- */
 extern const struct wcurve id_tc26_gost_3410_2012_256_paramSetTest;
 extern const struct wcurve id_tc26_gost_3410_2012_256_paramSetA;
 extern const struct wcurve id_rfc4357_gost_3410_2001_paramSetA;
 extern const struct wcurve id_rfc4357_gost_3410_2001_paramSetB;
 extern const struct wcurve id_rfc4357_gost_3410_2001_paramSetC;

/*! \brief Параметры кривой A из RFC 4357, включенные в состав рекомендаций Р 1323565.0.024-2019 */
 #define id_tc26_gost_3410_2012_256_paramSetB ( id_rfc4357_gost_3410_2001_paramSetA )
/*! \brief Параметры кривой B из RFC 4357, включенные в состав рекомендаций Р 1323565.0.024-2019 */
 #define id_tc26_gost_3410_2012_256_paramSetC ( id_rfc4357_gost_3410_2001_paramSetB )
/*! \brief Параметры кривой C из RFC 4357, включенные в состав рекомендаций Р 1323565.0.024-2019 */
 #define id_tc26_gost_3410_2012_256_paramSetD ( id_rfc4357_gost_3410_2001_paramSetC )

 extern const struct wcurve id_axel_gost_3410_2012_256_paramSet_N0;

/* ----------------------------------------------------------------------------------------------- */
/*                         параметры 512-ти битных эллиптических кривых                            */
/* ----------------------------------------------------------------------------------------------- */
 extern const struct wcurve id_tc26_gost_3410_2012_512_paramSetTest;
 extern const struct wcurve id_tc26_gost_3410_2012_512_paramSetA;
 extern const struct wcurve id_tc26_gost_3410_2012_512_paramSetB;
 extern const struct wcurve id_tc26_gost_3410_2012_512_paramSetC;
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup gf2n Конечные поля характеристики два
 @{ */
/*! \brief Умножение элемента поля на примитивный элемент.
    \details Макрос реализует умножение произвольного элемента поля \f$ \mathbb F_{2^{128}} \f$ на
    примитивный элемент поля. `s1` задает старшие 64 бита элемента, `s0` - младшие 64 бита.
    Степень расширения поля равняется 128, а многочлен,
    порождающий поле равен \f$ f(x) = x^{128} + x^7 + x^2 + x + 1 \in \mathbb F_2[x]\f$.           */
/* ----------------------------------------------------------------------------------------------- */
 #define ak_gf128_mul_theta(s1,s0) {\
   ak_uint64 n = s1&0x8000000000000000LL;\
   s1 <<= 1; s1 ^= ( s0 >> 63 ); s0 <<= 1;\
   if( n ) s0 ^= 0x87;\
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{64}}\f$. */
 dll_export void ak_gf64_mul_uint64( ak_pointer z, ak_pointer x, ak_pointer y );
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{128}}\f$. */
 dll_export void ak_gf128_mul_uint64( ak_pointer z, ak_pointer x, ak_pointer y );
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{256}}\f$. */
 dll_export void ak_gf256_mul_uint64( ak_pointer z, ak_pointer x, ak_pointer y );
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{512}}\f$. */
 dll_export void ak_gf512_mul_uint64( ak_pointer z, ak_pointer x, ak_pointer y );

#ifdef AK_HAVE_BUILTIN_CLMULEPI64
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{64}}\f$. */
 dll_export void ak_gf64_mul_pcmulqdq( ak_pointer z, ak_pointer x, ak_pointer y );
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{128}}\f$. */
 dll_export void ak_gf128_mul_pcmulqdq( ak_pointer z, ak_pointer a, ak_pointer b );
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{256}}\f$. */
 dll_export void ak_gf256_mul_pcmulqdq( ak_pointer z, ak_pointer a, ak_pointer b );
/*! \brief Умножение двух элементов поля \f$ \mathbb F_{2^{512}}\f$. */
 dll_export void ak_gf512_mul_pcmulqdq( ak_pointer z, ak_pointer a, ak_pointer b );

 #define ak_gf64_mul ak_gf64_mul_pcmulqdq
 #define ak_gf128_mul ak_gf128_mul_pcmulqdq
 #define ak_gf256_mul ak_gf256_mul_pcmulqdq
 #define ak_gf512_mul ak_gf512_mul_pcmulqdq
#else

 #define ak_gf64_mul ak_gf64_mul_uint64
 #define ak_gf128_mul ak_gf128_mul_uint64
 #define ak_gf256_mul ak_gf256_mul_uint64
 #define ak_gf512_mul ak_gf512_mul_uint64
#endif
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup enc Шифрование данных
 @{ */
/*! \brief Нелинейная перестановка для алгоритмов хеширования и блочного шифрования */
 typedef ak_uint8 sbox[256];

/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup mac Вычисление кодов целостности (хеширование и имитозащита)
 @{ */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция очистки контекста хеширования. */
 typedef int ( ak_function_context_clean )( ak_pointer );
/*! \brief Однораундовая функция сжатия, применяемая к одному или нескольким входным блокам. */
 typedef int ( ak_function_context_update )( ak_pointer, const ak_pointer , const size_t );
/*! \brief Функция завершения вычислений и получения конечного результата. */
 typedef int ( ak_function_context_finalize )( ak_pointer,
                                     const ak_pointer , const size_t , ak_pointer , const size_t );
/*! \brief Функция создания контекста хеширования. */
 typedef int ( ak_function_hash_create )( ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Максимальный размер блока входных данных в октетах (байтах). */
 #define ak_mac_max_buffer_size (64)

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Контекст алгоритма итерационного сжатия. */
/*! Класс предоставляет интерфейс для реализации процедруры сжатия данных фрагментами произвольной длины.
    Данная процедура может применяться в алгоритмах хеширования, выработки имитовставки и т.п.*/
/* ----------------------------------------------------------------------------------------------- */
 typedef struct mac {
  /*! \brief Размер входного блока данных (в октетах) */
   size_t bsize;
  /*! \brief Текущее количество данных во внутреннем буффере. */
   size_t length;
  /*! \brief Внутренний буффер для хранения входных данных. */
   ak_uint8 data[ ak_mac_max_buffer_size ];
  /*! \brief Указатель на контекст, содержащий внутреннее состояние алгоритма сжатия. */
   ak_pointer ctx;
  /*! \brief Функция очистки контекста ctx */
   ak_function_context_clean *clean;
  /*! \brief Функция обновления состояния контекста ctx  */
   ak_function_context_update *update;
  /*! \brief Функция завершения вычислений и получения конечного результата */
   ak_function_context_finalize *finalize;
 } *ak_mac;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура для хранения внутренних данных функций хеширования семейства Стрибог. */
/* ----------------------------------------------------------------------------------------------- */
 typedef struct streebog {
 /*! \brief Вектор h - временный */
  ak_uint64 h[8];
 /*! \brief Вектор n - временный */
  ak_uint64 n[8];
 /*! \brief Вектор  \f$ \Sigma \f$ - контрольная сумма */
  ak_uint64 sigma[8];
 /*! \brief Размер блока выходных данных (хеш-кода)*/
  size_t hsize;
} *ak_streebog;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Бесключевая функция хеширования. */
/*! \details Класс предоставляет интерфейс для реализации бесключевых функций хеширования, построенных
    с использованием итеративных сжимающих отображений. В настоящее время
    с использованием класса \ref hash реализованы следующие отечественные алгоритмы хеширования
     - Стрибог256,
     - Стрибог512.

  Перед началом работы контекст функции хэширования должен быть инициализирован
  вызовом одной из функций инициализации, например, функции ak_hash_context_create_streebog256()
  или функции ak_hash_context_create_streebog512().
  После завершения вычислений контекст должен быть освобожден с помощью функции
  ak_hash_context_destroy().                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 typedef struct hash {
  /*! \brief OID алгоритма хеширования */
   ak_oid oid;
  /*! \brief Контекст итерационного сжатия. */
   struct mac mctx;
  /*! \brief Внутренние данные контекста */
   union {
   /*! \brief Структура алгоритмов семейства Стрибог. */
    struct streebog sctx;
   } data;
 } *ak_hash;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция инициализации контекста начальными значениями. */
 dll_export int ak_mac_create( ak_mac , const size_t , ak_pointer ,
     ak_function_context_clean * , ak_function_context_update * , ak_function_context_finalize * );
/*! \brief Функция удаления контекста. */
 dll_export int ak_mac_destroy( ak_mac );
/*! \brief Очистка контекста сжимающего отображения. */
 dll_export int ak_mac_clean( ak_mac );
/*! \brief Обновление состояния контекста сжимающего отображения. */
 dll_export int ak_mac_update( ak_mac , const ak_pointer , const size_t );
/*! \brief Обновление состояния и вычисление результата применения сжимающего отображения. */
 dll_export int ak_mac_finalize( ak_mac , const ak_pointer , const size_t , ak_pointer , const size_t );
/*! \brief Применение сжимающего отображения к заданной области памяти. */
 dll_export int ak_mac_ptr( ak_mac , ak_pointer , const size_t , ak_pointer , const size_t );
/*! \brief Применение сжимающего отображения к заданному файлу. */
 dll_export int ak_mac_file( ak_mac , const char* , ak_pointer , const size_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация контекста функции бесключевого хеширования ГОСТ Р 34.11-2012 (Стрибог256). */
 dll_export int ak_hash_create_streebog256( ak_hash );
/*! \brief Инициализация контекста функции бесключевого хеширования ГОСТ Р 34.11-2012 (Стрибог512). */
 dll_export int ak_hash_create_streebog512( ak_hash );
/*! \brief Инициализация контекста функции бесключевого хеширования по заданному OID алгоритма. */
 dll_export int ak_hash_create_oid( ak_hash, ak_oid );
/*! \brief Уничтожение контекста функции хеширования. */
 dll_export int ak_hash_destroy( ak_hash );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция возвращает размер вырабатываемого хеш-кода (в октетах). */
 dll_export size_t ak_hash_get_tag_size( ak_hash );
/*! \brief Функция возвращает размер блока входных данных, обрабатываемого функцией хеширования (в октетах). */
 dll_export size_t ak_hash_get_block_size( ak_hash );
/*! \brief Очистка контекста алгоритма хеширования. */
 dll_export int ak_hash_clean( ak_hash );
/*! \brief Обновление состояния контекста хеширования. */
 dll_export int ak_hash_update( ak_hash , const ak_pointer , const size_t );
/*! \brief Обновление состояния и вычисление результата применения алгоритма хеширования. */
 dll_export int ak_hash_finalize( ak_hash , const ak_pointer , const size_t , ak_pointer , const size_t );
/*! \brief Хеширование заданной области памяти. */
 dll_export int ak_hash_ptr( ak_hash , const ak_pointer , const size_t , ak_pointer , const size_t );
/*! \brief Хеширование заданного файла. */
 dll_export int ak_hash_file( ak_hash , const char*, ak_pointer , const size_t );
/** @} */

#ifdef __cplusplus
} /* конец extern "C" */
#endif
#endif

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                     libakrypt.h */
/* ----------------------------------------------------------------------------------------------- */
