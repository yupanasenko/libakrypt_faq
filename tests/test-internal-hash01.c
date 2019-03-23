/* Пример, иллюстрирующий создание, удаление контекстов функции хеширования,
   а также вычисление хеш-кода для данных с известной длиной.
   Пример использует неэкспортируемые функции библиотеки.

   test-internal-hash01.c
*/

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <ak_hash.h>
 #include <ak_parameters.h>

 int main( void )
{
  char *str = NULL;
  struct hash ctx_one;    /* объект, размещаемый в статической памяти (стеке) */
  ak_buffer result_one = NULL; /* результат вычислений, помещаемый в кучу */
  int error = ak_error_ok, exitcode = EXIT_FAILURE;
  ak_uint8 some_pointer[7] = { 0, 1, 2, 3, 4, 5, 6 }; /* данные для хеширования */

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* статический объект существует, но он требует инициализации */
  if(( error = ak_hash_context_create_streebog256( &ctx_one )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect initialization of hash context" );
    goto exit_label;
  }

 /* вычисляем хеш-код от заданной области памяти (используя статический объект) */
  result_one =
    ak_hash_context_ptr( &ctx_one, some_pointer, sizeof( some_pointer ), NULL );
  printf("hash [1]: %s ", str = ak_buffer_to_hexstr( result_one, ak_false ));

 /* сравниваем полученный результат с ожидаемым */
  if( !strncmp( str,
       "C087BAD4C0FDC5622873294B5D9C3B790A9DC55FB29B1758D5154ADC2310F189", 32 )) {
    printf("Ok\n");
    exitcode = EXIT_SUCCESS;
  } else printf("Wrong\n");

 /* освобождаем временную память */
  free( str );
  result_one = ak_buffer_delete( result_one );

  exit_label: /* конец рабочего примера */
   /* уничтожаем статический объект */
    ak_hash_context_destroy( &ctx_one );
   /* завершаем библиотеку */
    ak_libakrypt_destroy();

 return exitcode;
}
