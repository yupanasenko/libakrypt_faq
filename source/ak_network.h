/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_network.h                                                                              */
/*  - содержит предварительное описание функций для работы с сетью.                                */
/* ----------------------------------------------------------------------------------------------- */
 #ifndef __AK_NETWORK_H__
 #define __AK_NETWORK_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief  Определение сокета, не зависящее от типа операционной системы. */
#ifdef LIBAKRYPT_HAVE_WINDOWS_H
 typedef SOCKET ak_socket;
 #define ak_network_undefined_socket  ( INVALID_SOCKET )
#else
 typedef int ak_socket;
 #define ak_network_undefined_socket                (-1)
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief  Тип функции низкого уровня для чтения из сокета. */
 typedef ssize_t ( fiot_function_socket_write )( ak_socket , const void *, size_t );
/*! \brief  Тип функции низкого уровня для записи в сокета. */
 typedef ssize_t ( fiot_function_socket_read )( ak_socket , void *, size_t );

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_WINDOWS_H
 ssize_t ak_network_write_win( ak_socket , const void *, size_t );
 ssize_t ak_network_read_win( ak_socket , void *, size_t );
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция создания сокета. */
 ak_socket ak_network_socket( int , int , int );
/*! \brief Функция закрытия сокета. */
 int ak_network_close( ak_socket );

/*! \brief Функция устанавливает соединение с сокетом. */
 int ak_network_connect( ak_socket , int , const char * , ak_uint32 );


#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                   ak_network.h  */
/* ----------------------------------------------------------------------------------------------- */
