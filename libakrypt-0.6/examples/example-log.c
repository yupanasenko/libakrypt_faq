 #include <stdio.h>
 #include <libakrypt.h>

/* определим пользовательскую функцию аудита */
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
 /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) {
    return ak_libakrypt_destroy();
  }

 /* выводим тестовое сообщение */
  ak_log_set_message( "Default audit: simple message" );

 /* устанавливаем свою собственную функцию аудита */
   ak_log_set_function( ak_function_log_user );

 /* выводим еще одно тестовое сообщение */
   ak_log_set_message( "User audit: another simple message" );

 /* сообщения, выводимые при остановке баиблиотеки,
    также выводятся с использованием установленной
    пользователем функции ak_function_log_user()   */
 return ak_libakrypt_destroy();
}
