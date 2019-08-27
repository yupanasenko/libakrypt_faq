/* Тестовый пример, иллюстрирующий работу генератора, считывающего
   случайные данные из сокета домена unix.
   Одновременно в примере реализуется простейший сервер генерации случайных данных.
   Пример использует неэкспортируемые функции.

   test-internal-random03.c
*/

 #include <time.h>
 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
 #include <unistd.h>
 #include <ak_random.h>

 #include <arpa/inet.h>
 #include <sys/un.h>
 #include <unistd.h>
 #include <errno.h>
 #include <signal.h>
 #include <sys/wait.h>
 #include <sys/socket.h>

 int client( void );
 int server( void );
 static void callback( int signo )
{
  int stat;
  switch( signo )
 {
   case SIGCHLD: while( waitpid( -1, &stat, WNOHANG ) > 0 ) { };
                 break;
 }
}

 int main( void )
{
  int error = EXIT_SUCCESS;

  printf("unix domain socket random generator test for libakrypt, version %s\n", ak_libakrypt_version( ));
  if( !ak_libakrypt_create( NULL )) return ak_libakrypt_destroy();
 /* устанавливаем максимальный уровень аудита */
  ak_log_set_level( ak_log_maximum );
  signal( SIGCHLD, callback );

  switch( fork( )) {
   case -1: return EXIT_FAILURE;
   case  0: /*  потомок */
            error = client(); /* запускаем клиентскую часть */
            break;
   default: /* родитель */
            close(0);
            close(1);
            close(2);
            error = server(); /* стартуем сервер генерации данных */
            break;
  }
  ak_libakrypt_destroy();
 return error;
}

 int client( void )
{
  int error;
  char str[512];
  unsigned int len = 1;
  ak_uint8 buffer[255];
  struct random generator;

  sleep(1);
  if(( error = ak_random_context_create_unix_domain_socket( &generator,
                       "test-internal-random03.socket", 5 )) != ak_error_ok ) return EXIT_FAILURE;

  printf("input size of random data [0 - exit]\n");
  while( len > 0 ) {
     printf("> "); scanf( "%u", &len );

     if( len > 255 ) len = 255;
     if( len > 0 ) {
       printf("len %3u [", len );
       if(( error = ak_random_context_random( &generator,
                                     buffer, ak_min( 255, (ssize_t)len ))) != ak_error_ok ) {
         ak_random_context_destroy( &generator );
         return ak_error_message( error, __func__, "random data generation error" );
       }
       ak_ptr_to_hexstr_static( buffer, ak_min( 255, len ), str, sizeof( str ), ak_false );
       printf("%s]\n", str );
     }
  }
  printf("exiting ...\n");
  ak_random_context_destroy( &generator );
 return EXIT_SUCCESS;
}

/* реализация сервера только демонстрирует его работу
   код содержащийся ниже не рекомендуется использоваться в приложениях */
 int server( void )
{
  int s, s2;
  size_t size, count = 0;
  socklen_t t, len;
  struct random generator;
  struct sockaddr_un local, remote;

 /* создаем сокет */
  if(( s = socket( AF_UNIX, SOCK_STREAM, 0 )) == -1 )
    return ak_error_message_fmt( s, __func__, "socket error (%s)", strerror( errno ));

  ak_error_message( ak_error_ok, "", "SOCKET OK" );

 /* связываем сокет с заданным файлом (сокетом домена unix) */
  memset( &local, 0, sizeof( struct sockaddr_un ));
  local.sun_family = AF_UNIX;
  strcpy( local.sun_path, "test-internal-random03.socket" );
  unlink( local.sun_path ); /* удаляем файл, если существует */
  len = (socklen_t)( strlen( local.sun_path ) + sizeof( local.sun_family ));
  if( bind( s, (struct sockaddr *)&local, len ) == -1)
    return ak_error_message_fmt( -1, __func__, "bind error (%s)", strerror( errno ));

  ak_error_message( ak_error_ok, "", "BIND OK" );


 /* переходим в режим прослушивания */
  if( listen( s, 5 ) == -1 )
    return ak_error_message_fmt( -1, __func__, "listen error (%s)", strerror( errno ));

  ak_error_message( ak_error_ok, "", "LISTEN OK" );

 /* выполняем процесс получения длин и возврата случайных последовательностей */
  do {
    size_t i = 0;
    ssize_t cnt = 0;
    ak_uint32 buffer;

    t = sizeof( struct sockaddr_un );
    memset( &remote, 0, sizeof( struct sockaddr_un ));

    if(( s2 = accept(s, (struct sockaddr *)&remote, (socklen_t *)&t )) == -1)
      return ak_error_message_fmt( -1, __func__, "accept error (%s)", strerror( errno ));

    ak_error_message( ak_error_ok, "", "ACCEPT OK" );

    /* считываем длину */
     buffer = 0;
     if( recv( s2, &buffer, 4, 0 ) != 4 ) {
       ak_error_message_fmt( ak_error_ok, "", "RECV %d", cnt );

       ak_error_message( -1, __func__, "wrong length");
       break;
     }
     size = ntohl( buffer );

     ak_error_message_fmt( ak_error_ok, "", "RECV OK [size = %u, number = %u]", size, count++ );

    /* создаем собственно генератор */
     if( ak_random_context_create_random( &generator ))
       return ak_error_message( -1, __func__, "generatir creation error" );

    /* отправляем данные */
     if( size > 0 ) {
       for( i = 0; i < size; i++ ) {
          ak_random_context_random( &generator, &buffer, 1 );
          send( s2, &buffer, 1, 0 );
       }
     }
     ak_random_context_destroy( &generator );
     close(s2);

    ak_error_message( ak_error_ok, "", "CLOSED OK" );
  } while( size );

 /* закрываем все и выходим */
  close(s);
  unlink( "test-internal-random03.socket" );

 return EXIT_SUCCESS;
}
