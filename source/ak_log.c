/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2014, 2015, 2016 by Axel Kenzo, axelkenzo@mail.ru                               */
/*   All rights reserved.                                                                          */
/*                                                                                                 */
/*   Redistribution and use in source and binary forms, with or without modification, are          */
/*   permitted provided that the following conditions are met:                                     */
/*                                                                                                 */
/*   1. Redistributions of source code must retain the above copyright notice, this list of        */
/*      conditions and the following disclaimer.                                                   */
/*   2. Redistributions in binary form must reproduce the above copyright notice, this list of     */
/*      conditions and the following disclaimer in the documentation and/or other materials        */
/*      provided with the distribution.                                                            */
/*   3. Neither the name of the copyright holder nor the names of its contributors may be used     */
/*      to endorse or promote products derived from this software without specific prior written   */
/*      permission.                                                                                */
/*                                                                                                 */
/*   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS   */
/*   OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF               */
/*   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL        */
/*   THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, */
/*   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE */
/*   GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED    */
/*   AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     */
/*   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED  */
/*   OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/*                                                                                                 */
/*   ak_log.c                                                                                      */
/* ----------------------------------------------------------------------------------------------- */
 #include <libakrypt.h>
 #include <ak_libakrypt.h>
 #ifndef _MSC_VER
  #ifndef __MINGW32__
   #include <syslog.h>
  #endif
  #include <unistd.h>
 #endif

/* ----------------------------------------------------------------------------------------------- */
/*!  Переменная, содержащая в себе код последней ошибки                                            */
 static int ak_errno = ak_error_ok;

/* ----------------------------------------------------------------------------------------------- */
/*! Внутренний указатель на функцию аудита                                                         */
 static ak_function_log *ak_function_log_default = NULL;
 static pthread_mutex_t ak_function_log_default_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ----------------------------------------------------------------------------------------------- */
 int ak_error_set_value( const int value )
{
  return ( ak_errno = value );
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_error_get_value( void )
{
  return ak_errno;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Явное определение функции аудита

   Функция устанавливает в качестве основного обработчика
   вывода сообщений функцию, задаваемую указателем function. Если аргумент function равен NULL,
   то используется функция по-умолчанию.
   Выбор функции по умолчанию зависит от операционной системы, под ОС Linux это вывод с
   использованием демона syslogd.

   @param function указатель на функцию вывода сообщений
   @return функция всегда возвращает ak_error_ok (ноль).                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_log_set_function( ak_function_log *function )
{
  pthread_mutex_lock( &ak_function_log_default_mutex );
  if( function != NULL ) ak_function_log_default = function;
   else {
    #ifdef __linux__
      ak_function_log_default = ak_function_log_syslog;
    #else
      ak_function_log_default = ak_function_log_stderr;
    #endif
   }
  pthread_mutex_unlock( &ak_function_log_default_mutex );
  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция использует установленную ранее функцию-обработчик сообщений. Если сообщение,
    или обработчик не определены (равны NULL) возвращается код ошибки.
    @param message выводимое сообщение
    @return в случае успеха, возвращается ak_error_ok (ноль). В случае возникновения ошибки,
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_log_set_message( const char *message )
{
  int result = 0;
  if( ak_function_log_default == NULL ) return ak_error_set_value( ak_error_null_pointer );
  if( message == NULL ) {
    ak_error_message( ak_error_null_pointer, "using a NULL string for message", __func__ );
  } else {
       pthread_mutex_lock( &ak_function_log_default_mutex );
       result = ak_function_log_default( message );
       pthread_mutex_unlock( &ak_function_log_default_mutex );
      return result;
    }
 return ak_error_ok;
}

#ifdef __linux__
/* ----------------------------------------------------------------------------------------------- */
/*! @param message выводимое сообщение
    @return в случае успеха, возвращается ak_error_ok (ноль). В случае возникновения ошибки,
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_function_log_syslog( const char *message )
{
  if( message != NULL ) syslog(  LOG_AUTHPRIV|LOG_NOTICE, "%s", message );
 return ak_error_ok;
}
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! @param message выводимое сообщение
    @return в случае успеха, возвращается ak_error_ok (ноль). В случае возникновения ошибки,
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_function_log_stderr( const char *message )
{
  if( message != NULL ) fprintf( stderr, "%s\n", message );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция формирует строку специального вилда и выводит ее в логгер с помомощью функции
    ak_log_set_message()

    @param code код ошибки
    @param message читаемое (понятное для пользователя) сообщение
    @param function имя функции, вызвавшей ошибку                                                  */
/* ----------------------------------------------------------------------------------------------- */
 void ak_error_message( const int code, const char *message, const char *function )
{
 /* здесь мы выводим в логгер строку вида [pid] function: message (code: n)                        */
  char error_event_string[1024];
  memset( error_event_string, 0, 1024 );
#ifdef _MSC_VER
  ak_snprintf( error_event_string, 1023, "[%d] %s(): %s (code: %d)",
                                                GetCurrentProcessId(), function, message, code );
#else
  ak_snprintf( error_event_string, 1023, "[%d] %s(): %s (code: %d)",
                                                             getpid(), function, message, code );
#endif
  ak_log_set_message( error_event_string );
  ak_error_set_value( code );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param code код ошибки
    @param message1 читаемое (понятное для пользователя) сообщение (первая часть)
    @param message1 читаемое (понятное для пользователя) сообщение (вторая часть)
    @param function имя функции, вызвавшей ошибку                                                  */
/* ----------------------------------------------------------------------------------------------- */
 void ak_error_message_str( const int code, const char *message1,
                                                        const char *message2, const char *function )
{
 /* здесь мы выводим в логгер строку вида [pid] function: message1 message2 (code: n)              */
  char error_event_string[1024];
  memset( error_event_string, 0, 1024 );
#ifdef _MSC_VER
  ak_snprintf( error_event_string, 1023, "[%d] %s(): %s %s (code: %d)",
                                         GetCurrentProcessId(), function, message1, message2, code );
#else
  ak_snprintf( error_event_string, 1023, "[%d] %s(): %s %s (code: %d)",
                                                  getpid(), function, message1, message2, code );
#endif
  ak_log_set_message( error_event_string );
  ak_error_set_value( code );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example example-log.c                                                                         */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_log.c  */
/* ----------------------------------------------------------------------------------------------- */
