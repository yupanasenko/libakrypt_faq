 #include <stdio.h>
 #include <stdlib.h>
 #include <libakrypt-base.h>

/* определим пользовательскую функцию аудита
   данная функция использует файл example-log.c.log
   для вывода сообщений от библиотеки. При этом
   происходит накопление сообщений (файл открывается в режиме дополнения) */
 int ak_function_log_user( const char *message )
{
  FILE *fp = fopen( "example-log.c.log", "a+" );
  /* функция выводит сообщения в заданный файл */
   if( !fp ) return ak_error_open_file;
   fprintf( fp, "%s\n", message );
   if( fclose(fp) == EOF ) return ak_error_access_file;
 return ak_error_ok;
}

 int main( void )
{
 /* по-умолчанию сообщения об ошибках выволятся в журналы syslog
    мы изменяем стандартный обработчик, на вывод сообщений в консоль */
  ak_log_set_function( ak_function_log_stderr );

 /* выводим тестовые сообщения, иллюстрирующие работу функций аудита */
  ak_log_set_message( "default audit: simple message" );
  ak_error_message( ak_error_null_pointer, __func__, "simple message" );
  ak_error_message_fmt( ak_error_access_file, __func__,
                        "third message with parameters: %s & %x", "weight", 32 );

 /* устанавливаем свою собственную функцию аудита - вывод в файл */
   ak_log_set_function( ak_function_log_user );

 /* выводим тестовые сообщения, иллюстрирующие работу функций аудита */
   ak_log_set_message( " user audit: another simple message" );
   ak_error_message( ak_error_null_pointer, __func__, "simple message" );
   ak_error_message_fmt( ak_error_access_file, __func__,
                        "third message with parameters: %s & %x", "weight", 32 );

 /* в заключение, демонстрируем вызов функции ak_printf,
    которая также может быть использована для аудита выполнения программы */
   ak_printf( ak_function_log_stderr,
                   "user's message number %u from %s() function", 11, __func__ );
   ak_printf( ak_function_log_user,
                   "user's message number %u from %s() function", 12, __func__ );

 return EXIT_SUCCESS;
}
