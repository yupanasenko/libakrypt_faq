#include <stdio.h>
#include <libakrypt.h>

/* определяем функцию, которая должна выполять содержательую работу
                        по разбору данных, считываемых из ini-файла */
 int user_handler( void *user , const char *section , const char *name , const char *value )
{
 printf("section [%s]: name [%s] = value [%s]\n", section, name, value );
 return 1; /* ненулевое значение - успешное завершение обработчика */
}

 int main( void )
{
 const char *string =
   "[example-ini]\n"
   "  file-name = example-ini.c\n"
   "  description = used as example for reading ini files\n"; 

/* инициализируем библиотеку, в случае возникновения ошибки завершаем работу */
 if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
   return ak_libakrypt_destroy();

 if( ak_ini_parse_string( string, user_handler, NULL ) != ak_error_ok )
   printf("incorrect parsing of test string\n");
  
 return ak_libakrypt_destroy();
}
