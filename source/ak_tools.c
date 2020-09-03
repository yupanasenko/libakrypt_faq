/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_tools.с                                                                                */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt-base.h>

/* ----------------------------------------------------------------------------------------------- */
#ifdef AK_HAVE_SYSLOG_H
 #include <syslog.h>
#endif

#ifdef AK_HAVE_UNISTD_H
 #include <unistd.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
/*!  Переменная, содержащая в себе код последней ошибки                                            */
 static int ak_errno = ak_error_ok;
 static int ak_log_level = ak_log_standard;

/* ----------------------------------------------------------------------------------------------- */
/*! Внутренний указатель на функцию аудита                                                         */
 static ak_function_log *ak_function_log_default =
  #ifdef AK_HAVE_SYSLOG_H
    ak_function_log_syslog;
  #else
    ak_function_log_stderr;
  #endif

#ifdef AK_HAVE_PTHREAD
 static pthread_mutex_t ak_function_log_default_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Cтатическая переменная для вывода сообщений. */
 static char ak_static_buffer[1024];

/* ----------------------------------------------------------------------------------------------- */
 #define AK_START_RED_STRING ("\x1b[31m")
 #define AK_END_RED_STRING ("\x1b[0m")

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Cтатическая переменные для окрашивания кодов и выводимых сообщений. */
 static char *ak_error_code_start_string = "";
 static char *ak_error_code_end_string = "";
#ifndef _WIN32
 static char *ak_error_code_start_red_string = AK_START_RED_STRING;
 static char *ak_error_code_end_red_string = AK_END_RED_STRING;
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! Все сообщения библиотеки могут быть разделены на три уровня.

    \li Первый уровень аудита определяется константой \ref ak_log_none. На этом уровне выводятся
    только сообщения об ошибках.

    \li Второй уровень аудита определяется константой \ref ak_log_standard. На этом уровене
    выводятся все сообщения из первого уровня, а также сообщения, регламентируемые нормативными
    документами.

    \li Третий (максимальный) уровень аудита определяется константой \ref ak_log_maximum.
    На этом уровне выводятся все сообщения, доступные на первых двух уровнях, а также
    сообщения отладочного характера, позволяющие проследить логику работы функций библиотеки.

    \param level Уровень аудита, может принимать значения \ref ak_log_none,
    \ref ak_log_standard и \ref ak_log_maximum

    \note Допускается передавать в функцию любое целое число, не превосходящее 16.
    Однако для всех значений от \ref ak_log_maximum  до 16 поведение функции аудита
    будет одинаковым. Дополнительный диапазон предназначен для приложений библиотеки.

    \return Функция возвращает новое значение уровня аудита.                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_log_set_level( int level )
{
   if( level < 0 ) return ( ak_log_level = ak_log_none );
   if( level > 16 ) return ( ak_log_level = 16 );
 return ( ak_log_level = level );
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_log_get_level( void )
{
 return ak_log_level;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \b Внимание. Функция экспортируется.
    \param value Код ошибки, который будет установлен. В случае, если значение value положительно,
    то код ошибки полагается равным величине \ref ak_error_ok (ноль).
    \return Функция возвращает устанавливаемое значение.                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_error_set_value( const int value )
{
  return ( ak_errno = value );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \b Внимание. Функция экспортируется.
    \return Функция возвращает текущее значение кода ошибки. Данное значение не является
    защищенным от возможности изменения различными потоками выполнения программы.                  */
/* ----------------------------------------------------------------------------------------------- */
 int ak_error_get_value( void )
{
  return ak_errno;
}

#ifdef AK_HAVE_SYSLOG_H
/* ----------------------------------------------------------------------------------------------- */
/*! \param message Выводимое сообщение.
    \return В случае успеха, возвращается ak_error_ok (ноль). В случае возникновения ошибки,
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_function_log_syslog( const char *message )
{
 #ifdef __linux__
   int priority = LOG_AUTHPRIV | LOG_NOTICE;
 #else
   int priority = LOG_USER;
 #endif
  if( message != NULL ) syslog( priority, "%s", message );
 return ak_error_ok;
}
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! \param message Выводимое сообщение
    \return В случае успеха, возвращается ak_error_ok (ноль). В случае возникновения ошибки,
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_function_log_stderr( const char *message )
{
  if( message != NULL ) {
   #ifdef AK_HAVE_WINDOWS_H
     fprintf( stderr, "%s\n", message );
   #else
     struct file file = { 2, 0, 0 };
     ak_file_printf( &file, "%s\n", message );
   #endif
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция устанавливает в качестве основного обработчика
    вывода сообщений функцию, задаваемую указателем function. Если аргумент function равен NULL,
    то используется функция по-умолчанию.
    Выбор того, какая именно функция будет установлена по-умолчанию, не фискирован.
    В текущей версии библиотеки он зависит от используемой операционной системы, например,
    под ОС Linux это вывод с использованием демона syslogd.

    \param function Указатель на функцию вывода сообщений.
    \return Функция всегда возвращает ak_error_ok (ноль).                                          */
/* ----------------------------------------------------------------------------------------------- */
 int ak_log_set_function( ak_function_log *function )
{
#ifdef AK_HAVE_PTHREAD
  pthread_mutex_lock( &ak_function_log_default_mutex );
#endif
  if( function != NULL ) {
    ak_function_log_default = function;
    if( function == ak_function_log_stderr ) { /* раскрашиваем вывод кодов ошибок */
      #ifndef _WIN32
        ak_error_code_start_string = ak_error_code_start_red_string;
        ak_error_code_end_string = ak_error_code_end_red_string;
      #endif
    } else { /* в остальных случаях, убираем раскраску вывода */
             ak_error_code_start_string = "";
             ak_error_code_end_string = "";
           }
  }
   else {
    #ifdef AK_HAVE_SYSLOG_H
      ak_function_log_default = ak_function_log_syslog;
    #else
      ak_function_log_default = ak_function_log_stderr;
    #endif
   }
#ifdef AK_HAVE_PTHREAD
  pthread_mutex_unlock( &ak_function_log_default_mutex );
#endif
  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция использует установленную ранее функцию-обработчик сообщений. Если сообщение,
    или обработчик не определены (равны NULL) возвращается код ошибки.

    \param message выводимое сообщение
    \return в случае успеха, возвращается ak_error_ok (ноль). В случае возникновения ошибки,
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_log_set_message( const char *message )
{
  int result = ak_error_ok;
  if( ak_function_log_default == NULL ) return ak_error_set_value( ak_error_undefined_function );
  if( message == NULL ) {
    return ak_error_message( ak_error_null_pointer, __func__ , "use a null string for message" );
  } else {
          #ifdef AK_HAVE_PTHREAD
           pthread_mutex_lock( &ak_function_log_default_mutex );
          #endif
           result = ak_function_log_default( message );
          #ifdef AK_HAVE_PTHREAD
           pthread_mutex_unlock( &ak_function_log_default_mutex );
          #endif
      return result;
    }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param str Строка, в которую помещается результат (сообщение)
    \param size Максимальный размер помещаемого в строку str сообщения
    \param format Форматная строка, в соответствии с которой формируется сообщение

    \return Функция возвращает значение, которое вернул вызов системной (библиотечной) функции
    форматирования строки.                                                                         */
/* ----------------------------------------------------------------------------------------------- */
 int ak_snprintf( char *str, size_t size, const char *format, ... )
{
  int result = 0;
  va_list args;
  va_start( args, format );

 #ifdef _MSC_VER
  #if _MSC_VER > 1310
    result = _vsnprintf_s( str, size, size, format, args );
  #else
    result = _vsnprintf( str, size, format, args );
  #endif
 #else
  result = vsnprintf( str, size, format, args );
 #endif
  va_end( args );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция устанавливает текущее значение кода ошибки, формирует строку специального вида и
    выводит сформированную строку в логгер с помомощью функции ak_log_set_message().

    \param code Код ошибки
    \param message Читаемое (понятное для пользователя) сообщение
    \param function Имя функции, вызвавшей ошибку

    \hidecallgraph
    \hidecallergraph
    \return Функция возвращает установленный код ошибки.                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_error_message( const int code, const char *function, const char *message )
{
 /* здесь мы выводим в логгер строку вида [pid] function: message (code: n)                        */
  char error_event_string[1024];
  const char *br0 = "", *br1 = "():", *br = NULL;

  memset( error_event_string, 0, 1024 );
  if(( function == NULL ) || strcmp( function, "" ) == 0 ) br = br0;
    else br = br1;

#ifdef AK_HAVE_UNISTD_H
  if( code < 0 ) ak_snprintf( error_event_string, 1023, "[%d] %s%s %s (%scode: %d%s)",
                              getpid(), function, br, message,
                                    ak_error_code_start_string, code, ak_error_code_end_string );
   else ak_snprintf( error_event_string, 1023, "[%d] %s%s %s", getpid(), function, br, message );
#else
 #ifdef _MSC_VER
  if( code < 0 ) ak_snprintf( error_event_string, 1023, "[%d] %s%s %s (code: %d)",
                                             GetCurrentProcessId(), function, br, message, code );
   else ak_snprintf( error_event_string, 1023, "[%d] %s%s %s",
                                                   GetCurrentProcessId(), function, br, message );
 #else
   #error Unsupported path to compile, sorry ...
 #endif
#endif
  ak_log_set_message( error_event_string );
 return ak_error_set_value( code );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \param code Код ошибки
    \param function Имя функции, вызвавшей ошибку
    \param format Форматная строка, в соответствии с которой формируется сообщение
    \hidecallgraph
    \hidecallergraph
    \return Функция возвращает установленный код ошибки.                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_error_message_fmt( const int code, const char *function, const char *format, ... )
{
  va_list args;
  va_start( args, format );
  memset( ak_static_buffer, 0, sizeof( ak_static_buffer ));

 #ifdef _MSC_VER
  #if _MSC_VER > 1310
    _vsnprintf_s( ak_static_buffer,
                  sizeof( ak_static_buffer ), sizeof( ak_static_buffer ), format, args );
  #else
    _vsnprintf( ak_static_buffer, sizeof( ak_static_buffer), format, args );
  #endif
 #else
   vsnprintf( ak_static_buffer, sizeof( ak_static_buffer ), format, args );
 #endif
   va_end( args );

 return ak_error_message( code, function, ak_static_buffer );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example example-log.c                                                                         */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                     ak_tools.c  */
/* ----------------------------------------------------------------------------------------------- */
