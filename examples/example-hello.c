#include <stdio.h>
#include <libakrypt.h>

 int main( void )
{
 /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) {
    return ak_libakrypt_destroy();
  }

 /* ...
       здесь код Вашей программы

       в качестве примера мы выполняем динамическое
       тестирование криптографических механизмов с
       помощью функции  ak_libakrypt_dynamic_control_test();

                                                       ... */
 return ak_libakrypt_destroy();
}
