#include <stdio.h>
#include <libakrypt.h>

 int main( void )
{
  // инициализируем библиотеку. в случае возникновения ошибки завершаем работу
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) {
  return ak_libakrypt_destroy();
 }

 // ...
 //  здесь код Вашей программы
 // ...

 return ak_libakrypt_destroy();
}
