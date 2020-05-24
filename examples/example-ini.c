#include <stdio.h>
#include <libakrypt.h>

 /* пользовательская функция разбора полей конфигурационного файла */
 int handler( void *user , const char *section , const char *name , const char *value )
{
 printf("section [%s]: name [%s] = value [%s]\n", section, name, value );
 return 1; /* ненулевое значение - успешное завершение обработчика */
}

 int main( void )
{
  char hpath[FILENAME_MAX];

 /* инициализируем библиотеку, в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
    return ak_libakrypt_destroy();

  if( ak_libakrypt_create_filename( hpath, sizeof( hpath ), "libakrypt.conf", 0 ) != ak_error_ok )
    return ak_libakrypt_destroy();
   else printf("file: %s\n", hpath );

  if( ak_libakrypt_ini_parse( hpath, handler, NULL ) != ak_error_ok )
    printf("incorrect ini-file\n");

 return ak_libakrypt_destroy();
}
