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
     return ak_error_message_fmt( ak_error_close_socket, __func__,
                                                                "wrong socket closing [%s]", str );
   }
 #else // ( sock != ak_network_undefined_socket )
   if( sock != ak_network_undefined_socket ) {
     if( close( sock ) == -1 ) return ak_error_message_fmt( ak_error_close_socket, __func__,
                                                   "wrong socket closing [%s]", strerror( errno ));
   }

 #endif
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/* MinGW не поддерживает реализацию inet_pton(), поэтому приходится заниматься самодеятельностью и
   использовать внешний код

   Thanks to author: Paul Vixie, 1996.                                                             */
/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_WINDOWS_H
 #ifndef _MSC_VER
  #define NS_INADDRSZ  4

  int inet_pton4( const char *src, char *dst ) {
     ak_uint8 tmp[NS_INADDRSZ], *tp = NULL;
     int ch;
     int saw_digit = 0;
     int octets = 0;
     *(tp = tmp) = 0;

     while ((ch = *src++) != '\0')
     {
         if (ch >= '0' && ch <= '9')
         {
             ak_uint32 n = *tp * 10 + (ch - '0');

             if (saw_digit && *tp == 0)
                 return 0;

             if (n > 255)
                 return 0;

             *tp = n;
             if (!saw_digit)
             {
                 if (++octets > 4)
                     return 0;
                 saw_digit = 1;
             }
         }
         else if (ch == '.' && saw_digit)
         {
             if (octets == 4)
                 return 0;
             *++tp = 0;
             saw_digit = 0;
         }
         else
             return 0;
     }
     if (octets < 4)
         return 0;

     memcpy( dst, tmp, NS_INADDRSZ );
     return 1;
 }
 #endif
#endif

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
       if( family == AF_INET ) {
         if( inet_pton4( src, dst ) != 1 )
           return ak_error_message_fmt( ak_error_wrong_inet_pton, __func__,
                                                 "wrong address creation (%s)", strerror( errno ));
       } else return ak_error_message( ak_error_undefined_function, __func__,
                                                 "this function is undefined for AF_INET6 family");
   #endif
 #endif
 return ak_error_ok;
}

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
