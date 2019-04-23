/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 - 2019 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_network.с                                                                              */
/*  - содержит реализацию функций для работы с сетью.                                              */
/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_UNISTD_H
 #include <unistd.h>
#endif
#ifdef LIBAKRYPT_HAVE_SYSSOCKET_H
 #include <sys/socket.h>
#endif
#ifdef LIBAKRYPT_HAVE_WINDOWS_H
 #include <winsock2.h>
 #include <ws2tcpip.h>
#else
 #include <arpa/inet.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_network.h>

#ifdef LIBAKRYPT_HAVE_WINDOWS_H
/* ----------------------------------------------------------------------------------------------- */
 ssize_t ak_network_write_win( ak_socket sock, const void *buffer, size_t size )
{
  return send( sock, buffer, size, MSG_DONTROUTE );
}

/* ----------------------------------------------------------------------------------------------- */
 ssize_t ak_network_read_win( ak_socket sock, void *buffer, size_t size )
{
 return recv( sock, buffer, size, 0 );
}
#endif

/* ----------------------------------------------------------------------------------------------- */
 ak_socket ak_network_socket( int domain, int type, int protocol )
{
 #ifdef LIBAKRYPT_HAVE_WINDOWS_H
  char str[128];
 #endif
  ak_socket sock = socket( domain, type, protocol );

  if( sock == ak_network_undefined_socket ) {
 #ifdef LIBAKRYPT_HAVE_WINDOWS_H
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
 #ifdef LIBAKRYPT_HAVE_WINDOWS_H
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


/* domain AF_INET bkb AF_INET6 */
/* ----------------------------------------------------------------------------------------------- */
 int ak_network_connect( ak_socket sock, int domain, const char *addr, ak_uint32 port )
{
  struct sockaddr_in serv;

  memset( &serv, 0, sizeof( struct sockaddr_in ));
  serv.sin_family = domain;
  serv.sin_port = htons( port );

 #ifdef LIBAKRYPT_HAVE_WINDOWS_H
  if( InetPton( domain, addr, &( serv.sin_addr )) != 1 ) {
    char str[128];
    strerror_s( str, sizeof( str ),  WSAGetLastError( ));
    return ak_error_message_fmt( ak_error_wrong_inet_pton, __func__,
                                                              "wrong address creation (%s)", str );
  }
 #else
  if( inet_pton( domain, addr, &( serv.sin_addr )) <= 0 )
    return ak_error_message_fmt( ak_error_wrong_inet_pton, __func__,
                                                 "wrong address creation (%s)", strerror( errno ));
 #endif

  if( connect( sock, (struct sockaddr*) &serv, sizeof( serv )) ) {
 #ifdef LIBAKRYPT_HAVE_WINDOWS_H
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
