/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл libakrypt.h                                                                               */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __LIBAKRYPT_H__
#define    __LIBAKRYPT_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-base.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Попытка доступа к неопределенной опции библиотеки. */
 #define ak_error_wrong_option                 (-100)

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup tests Функции инициализации и тестирования библиотеки
 @{ */
/*! \brief Функция инициализации библиотеки. */
 dll_export int ak_libakrypt_create( ak_function_log * );
/*! \brief Функция завершает работу с библиотекой. */
 int ak_libakrypt_destroy( void );
/*! \brief Функция выполняет динамическое тестирование работоспособности криптографических преобразований. */
 dll_export bool_t ak_libakrypt_dynamic_control_test( void );
/** @} */

/* ----------------------------------------------------------------------------------------------- */
/** \addtogroup options Функции для работы с опциями библиотеки
 @{ */
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

/*! \brief Функция устанавливает режим совместимости криптографических преобразований с библиотекой openssl. */
 dll_export int ak_libakrypt_set_openssl_compability( bool_t );
/*! \brief Функция получает домашний каталог библиотеки. */
 dll_export int ak_libakrypt_get_home_path( char * , const size_t );
/*! \brief Функция создает полное имя файла в домашем каталоге библиотеки. */
 dll_export int ak_libakrypt_create_home_filename( char * , const size_t , char * , const int );
/** @} */

#ifdef __cplusplus
} /* конец extern "C" */
#endif
#endif

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                     libakrypt.h */
/* ----------------------------------------------------------------------------------------------- */
