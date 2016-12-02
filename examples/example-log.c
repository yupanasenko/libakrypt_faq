#include <stdio.h>
#include <libakrypt.h>

/* пользовательская функция аудита выводит сообшения в текстовый файл example-log.c.log */
 int ak_function_log_user( const char *message )
{
  FILE *fp = fopen( "example-log.c.log", "a+" );
  if( !fp ) return ak_error_open_file;
  fprintf( fp, "%s\n", message );
  if( fclose(fp) == EOF ) return ak_error_access_file;
  return ak_error_ok;
}

 int main( void )
{
 /* инициализируем библиотеку с функцией аудита  стандартный поток вывода ошибок */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) return ak_libakrypt_destroy();
 /* выводим тестовое сообщение */
  ak_log_set_message( "Default audit: simple test message" );
 /* теперь устанавливаем свою собственную функцию аудита */
  ak_log_set_function( ak_function_log_user );
 /* выводим тестовое сообщение */
  ak_log_set_message( "User audit: simple test message" );
 return ak_libakrypt_destroy();
}

