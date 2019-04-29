/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_network.с                                                                              */
/*  - содержит реализацию функций для работы с сетью.                                              */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_network.h>

#ifdef LIBAKRYPT_HAVE_STRING_H
 #include <string.h>
#endif
#ifdef LIBAKRYPT_HAVE_ERRNO_H
 #include <errno.h>
#endif
#ifdef LIBAKRYPT_HAVE_UNISTD_H
 #include <unistd.h>
#endif

#ifdef LIBAKRYPT_HAVE_WINDOWS_H
/* ----------------------------------------------------------------------------------------------- */
/*! \param sock Сокет, в который происходит запись.
    \param buffer Указатель на записываемые в сокет данные.
    \param size Размер данных в байтах.

    \return Функция возвращает количество записанных в сокет данных. Данное значение может быть
    меньше, чем значение параметра `size`.                                                         */
/* ----------------------------------------------------------------------------------------------- */
 ssize_t ak_network_write_win( ak_socket sock, const void *buffer, size_t size )
{
  return send( sock, buffer, size, MSG_DONTROUTE );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param sock Сокет, из которого происходит чтение.
    \param buffer Указатель на область памяти, в которую помещаются данные.
    \param size Размер считанных данных в байтах.

    \return Функция возвращает количество считанных из сокета данных. Данное значение может быть
    меньше, чем значение параметра `size`.                                                         */
/* ----------------------------------------------------------------------------------------------- */
 ssize_t ak_network_read_win( ak_socket sock, void *buffer, size_t size )
{
 return recv( sock, buffer, size, 0 );
}
#endif

/* ----------------------------------------------------------------------------------------------- */
 ak_socket ak_network_socket( int domain, int type, int protocol )
{
 #ifdef _MSC_VER // LIBAKRYPT_HAVE_WINDOWS_H
  char str[128];
 #endif
  ak_socket sock = socket( domain, type, protocol );

  if( sock == ak_network_undefined_socket ) {
 #ifdef _MSC_VER
    strerror_s( str, sizeof( str ), WSAGetLastError( ));
    ak_error_message_fmt( ak_error_open_socket, __func__, "wrong socket creation [%s]", str );
 #else
    ak_error_message_fmt( ak_error_open_socket, __func__,
                                             "wrong socket creation [%s]", strerror( errno ));
 #endif
  }
 return sock;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_network_close( ak_socket sock )
{
 #ifdef _MSC_VER //LIBAKRYPT_HAVE_WINDOWS_H
   char str[128];
   if( closesocket( sock ) == SOCKET_ERROR ) {
     strerror_s( str, sizeof( str ), WSAGetLastError( ));
     return ak_error_message_fmt( ak_error_close_socket, __func__, "wrong socket closing [%s]", str );
   }
 #else
   if( close( sock ) == -1 )
     return ak_error_message_fmt( ak_error_close_socket, __func__,
                                                      "wrong socket closing [%s]", strerror( errno ));
 #endif
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_network_inet_pton( int family, const char *src, void *dst )
{
 #ifndef LIBAKRYPT_HAVE_WINDOWS_H
   if( inet_pton( family, src, dst ) != 1 )
     return ak_error_message_fmt( ak_error_wrong_inet_pton, __func__,
                                                 "wrong address creation (%s)", strerror( errno ));
 #else
   #ifdef _MSC_VER
     if( InetPton( family, src, dst ) != 1 ) {
       char str[128];
       strerror_s( str, sizeof( str ),  WSAGetLastError( ));
       return ak_error_message_fmt( ak_error_wrong_inet_pton, __func__,
                                                               "wrong address creation (%s)", str );
     }
   #else
      xxx
   #endif
 #endif
 return ak_error_ok;
}

//   memset( saddr, 0, sizeof( union sock_addr ));
//   switch( family ) {
//     case AF_INET:
//       saddr->ipv4.sin_family = AF_INET;
//       saddr->ipv4.sin_port = htons( port );


//       break;
//     case AF_INET6:
//       saddr->ipv6.sin6_family = AF_INET6;
//       saddr->ipv6.sin6_port   = htons(port);
//       break;
//     default: return ak_error_message( ak_error_wrong_protocol_family,
//                                                         __func__, "using wrong protocol family" );
//   }

// #ifndef LIBAKRYPT_HAVE_WINDOWS_H
//   if( inet_pton( family, src, saddr ) != 1 )
//     return ak_error_message_fmt( ak_error_wrong_inet_pton, __func__,
//                                                 "wrong address creation (%s)", strerror( errno ));
// #else
//   #ifdef _MSC_VER
//     if( InetPton( family, src, saddr ) != 1 ) {
//       char str[128];
//       strerror_s( str, sizeof( str ),  WSAGetLastError( ));
//       return ak_error_message_fmt( ak_error_wrong_inet_pton, __func__,
//                                                               "wrong address creation (%s)", str );
//     }
//   #else
//      xxx
//   #endif
// #endif
// return ak_error_ok;



/* ----------------------------------------------------------------------------------------------- */
 int ak_network_connect( ak_socket sock, void *saddr )
{
  if( connect( sock, ( struct sockaddr* ) saddr, sizeof( struct sockaddr )) != 0 ) {
 #ifdef _MSC_VER // LIBAKRYPT_HAVE_WINDOWS_H
    char str[128];
    strerror_s( str, sizeof( str ),  WSAGetLastError( ));
    return ak_error_message_fmt( ak_error_connect_socket, __func__, "connect error (%s)", str );
 #else
    return ak_error_message_fmt( ak_error_connect_socket, __func__,
                                                       "connect error (%s)", strerror( errno ));
 #endif
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                   ak_network.c  */
/* ----------------------------------------------------------------------------------------------- */
