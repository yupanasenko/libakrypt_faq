/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2019 by Axel Kenzo, axelkenzo@mail.ru                                            */
/*                                                                                                 */
/*  Файл ak_random.с                                                                               */
/*  - содержит реализацию генератора псевдо-случайных чисел, получающего значения от сервера       */
/*    выработки ДСЧ. связь с сервером реализуется через механизм сокетов домена unix               */
/* ----------------------------------------------------------------------------------------------- */
 #include <sys/un.h>
 #include <sys/socket.h>
 #include <arpa/inet.h>

/* ----------------------------------------------------------------------------------------------- */
 #ifdef LIBAKRYPT_HAVE_STDLIB_H
  #include <stdlib.h>
 #else
  #error Library cannot be compiled without stdlib.h header
 #endif
 #ifdef LIBAKRYPT_HAVE_STRING_H
  #include <string.h>
 #else
  #error Library cannot be compiled without string.h header
 #endif
 #ifdef LIBAKRYPT_HAVE_SYSSELECT_H
  #include <sys/select.h>
 #endif
 #ifdef LIBAKRYPT_HAVE_ERRNO_H
  #include <errno.h>
 #endif
 #ifdef LIBAKRYPT_HAVE_UNISTD_H
  #include <unistd.h>
 #endif

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_random.h>
 #define filename_length   ( 256 )

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Класс для хранения файлового дескриптора открытого сокета. */
 typedef struct random_unix_domain_socket
{
 /*! \brief Имя файла, связанного с сокетом, из которого производится чтение. */
  char filename[filename_length];
 /*! \brief Тайм-аут  ожидания данных от сервера. */
  ssize_t timeout;
} *ak_random_unix_domain_socket;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция выработки случайных данных.
    \details В ходе выполнения функции реализуется протокол получения случайных данных из
    сокета домена unix и
    заполнение полученными данными области памяти, на которую указывает `out`.

    @param rnd контекст генератора псевдо-случайных чисел.
    @param out указатель на область памяти, в которую помещаются псевдо-случайные данные.
    @param size размер помещаемых данных, в байтах.

    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_random_unix_domain_socket_random( ak_random rnd,
                                                        const ak_pointer ptr, const ssize_t size )
{
  int sock = 0;
  ssize_t cnt = 0;
  socklen_t len = 0;
  ak_uint32 count = 0;
  struct sockaddr_un remote;
  size_t bound = 0, offset = 0;
  ak_random_unix_domain_socket uds = NULL;

  if( rnd == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                      "use a null pointer to a random generator" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                           "use a null pointer to output buffer" );
  if( size <= 0 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                         "use a output buffer with wrong length" );
 /* создаем сокет */
  if(( sock = socket( AF_UNIX, SOCK_STREAM, 0 )) == -1 ) {
   #ifdef LIBAKRYPT_HAVE_ERRNO_H
    return ak_error_message_fmt( ak_error_open_socket, __func__,
                                              "incorrect socket creation (%s)", strerror( errno ));
   #else
    return ak_error_message( ak_error_open_socket, __func__, "incorrect socket creation" );
   #endif
  }

 /* связываемся с сервером генерации случайных данных */
  uds = ( ak_random_unix_domain_socket ) rnd->data;
  memset( &remote, 0, sizeof( struct sockaddr_un ));
  remote.sun_family = AF_UNIX;
  memcpy( remote.sun_path, uds->filename,
                                      ak_min( sizeof( remote.sun_path ), strlen( uds->filename )));
  len = ( socklen_t )( strlen( remote.sun_path ) + sizeof( remote.sun_family ));
  if( connect( sock, (struct sockaddr *)&remote, len ) == -1 ) {
 #ifdef LIBAKRYPT_HAVE_ERRNO_H
    return ak_error_message_fmt( ak_error_connect_socket, __func__,
                          "incorrect connect with file %s (%s)", uds->filename, strerror( errno ));
 #else
    return ak_error_message_fmt( ak_error_connect_socket, __func__,
                                                 "incorrect connect with file %s", uds->filename );
 #endif
  }

 /* выполняем протокол получения данных
    в начале отправляем число запрашиваемых байт случайных данных */
  count = htonl( size );
  bound = sizeof( ak_uint32 ); offset = 0;

  wlab:
  if(( cnt = send( sock, ((ak_uint8 *)&count)+offset, bound, 0 )) != ( ssize_t )bound ) {
    if( cnt == -1 )
     #ifdef LIBAKRYPT_HAVE_ERRNO_H
      return ak_error_message_fmt( ak_error_write_data, __func__,
                                        "incorrect sending a data length (%s)", strerror( errno ));
     #else
      return ak_error_message( ak_error_write_data, __func__, "incorrect sending a data length" );
     #endif
      else { /* мы записали cnt байт, но меньше, чем ожидали  */
              ak_error_message_fmt( ak_error_ok, "", "PARTIAL SEND %d", cnt );
              offset += ( size_t )cnt; bound -= ( size_t )cnt; goto wlab;
           }
  }

 /* теперь считываем данные, выработанные сервером */
  bound = ( size_t )size; offset = 0;
  do {
   #ifdef LIBAKRYPT_HAVE_SYSSELECT_H
    fd_set fdset;
    struct timeval tv;

    tv.tv_usec = 0; tv.tv_sec = uds->timeout;
    FD_ZERO( &fdset );
    FD_SET( sock, &fdset );
    if( select( sock+1, &fdset, NULL, NULL, &tv ) <= 0 )
      return ak_error_message( ak_error_read_data_timeout, __func__, "read random data timeout" );
   #endif

    if(( cnt = recv( sock, ((ak_uint8 *)ptr)+offset, bound, 0 )) == -1 )
      return ak_error_message_fmt( ak_error_read_data, __func__,
                                                "read random data error [%s]", strerror( errno ));
    bound -= ( size_t )cnt; offset += ( size_t )cnt;
  } while( bound > 0 );

 /* в заключение закрываем сокет */
  close( sock );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация контекста генератора, считывающего случайные значения из
    сокета домена unix.

    \details Генератор представляет собой клиентскую часть, реализующую протокол получения данных
    из сокета, определяемого файлом `filename`. Протокол получения данных заключается в следующем:

   1. клиент (генератор) открывает сокет с заданным именем и посылает в него 4 байта,
      которые содержат количество длину запрашиваемых случайных данных. Данные передаются
      в сетевом порядке байт.

   2. клиент считывает из сокета запрошенное количество байт; если данные в сокете отсутствуют,
      то клиент блокирует выполнение программы и ожидает появления данных в течении
      заданного интервала данных. Если за время ожидания данные не получены, то возвращается
      сообщение об ошибке.

    @param generator Контекст создаваемого генератора.
    @param filename Имя файла, связанного с сокетом домена unix.
    @param timeout Интервал времени ожидания от сервера (в секундах).
    \return В случае успеха, функция возвращает \ref ak_error_ok. В противном случае
            возвращается код ошибки.                                                               */
/* ----------------------------------------------------------------------------------------------- */
 int ak_random_context_create_unix_domain_socket( ak_random generator,
                                                             const char *filename, ssize_t timeout )
{
  size_t len = 0;
  int error = ak_error_ok;
  ak_random_unix_domain_socket uds = NULL;

  if( generator == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                      "use a null pointer to a random generator" );
  if( filename == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                        "use a null pointer to socket file name" );
  if(( len = strlen( filename )) > filename_length - 1 )
    return ak_error_message_fmt( ak_error_out_of_memory, __func__ ,
                                 "filename has a length greather than %u bytes", filename_length );

  if(( error = ak_random_context_create( generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong initialization of random generator" );

  if(( uds = malloc( sizeof( struct random_unix_domain_socket ))) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__ ,
                     "incorrect memory allocation for an internal variables of random generator" );

 /* устанавливаем поля внутренней структуры */
  memset( uds->filename, 0, filename_length );
  memcpy( uds->filename, filename, len );
  uds->timeout = timeout; /* время, в секундах, для ожидания ответа от сервера */

 /* - для данного генератора oid не определен
    - функция generator->free определена в классе-родителе */
  generator->data = uds;
  generator->next = NULL;
  generator->randomize_ptr = NULL;
  generator->random = ak_random_unix_domain_socket_random;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*!  \example test-internal-random03.c                                                             */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_udsrandom.c  */
/* ----------------------------------------------------------------------------------------------- */
