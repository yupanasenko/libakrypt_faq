/* Пример, иллюстрирующий создание, удаление контекстов функции хеширования,
   а также вычисление хеш-кода для данных с известной длиной.
   Пример использует неэкспортируемые функции библиотеки.

   test-internal-hash01.c
*/

 #include <stdio.h>
 #include <ak_hash.h>

 int main( int argc, char *argv[] )
{
  char *str = NULL;
  struct hash ctx_one;    /* объект, размещаемый в статической памяти (стеке) */
  ak_hash ctx_two = NULL; /* объект, размещаемый в динамической памяти (куче) */
  int exitcode = EXIT_SUCCESS;
  ak_buffer result_one = NULL; /* результат вычислений, помещаемый в кучу */
  ak_uint8 result_two[64]; /* результат вычислений, помещаемый в стек */
  ak_uint8 some_pointer[7] = { 0, 1, 2, 3, 4, 5, 6 }; /* данные для хеширования */

 /* статический объект уже создан, он требует инициализации
    создаем объект в динамической памяти */
  ctx_two = malloc( sizeof( struct hash ));

 /* инициализируем статический объект */
  ak_hash_context_create_streebog256( &ctx_one );
 /* инициализируем динамический объект */
  ak_hash_context_create_streebog512( ctx_two );


 /* первый эксперимент
  * вычисляем хеш-код от заданной области памяти (используя статический объект) */
  result_one =
    ak_hash_context_ptr( &ctx_one, some_pointer, sizeof( some_pointer ), NULL );
  printf("hash [1]: %s\n", str = ak_buffer_to_hexstr( result_one, ak_false ));

 /* сравниваем полученный результат с ожидаемым */
  if( strncmp( str,
      "C087BAD4C0FDC5622873294B5D9C3B790A9DC55FB29B1758D5154ADC2310F189", 32 ) != 0 )
    exitcode = EXIT_FAILURE;

 /* освобождаем временную память */
  free( str );
  result_one = ak_buffer_delete( result_one );

 /* второй эксперимент
  * вычисляем хеш-код от заданного файла (используя динамический объект) */
  ak_hash_context_file( ctx_two, argv[0], result_two );
  if( ak_error_get_value() != ak_error_ok ) exitcode = EXIT_FAILURE;
  printf("hash [2]: %s\n", str = ak_ptr_to_hexstr( result_two, 64, ak_false ));

 /* освобождаем временную память */
  free( str );

 /* уничтожение статического объекта */
  ak_hash_context_destroy( &ctx_one );
 /* уничтожение динамического объекта и освобождение выделенной под него памяти */
  ctx_two  = ak_hash_context_delete( ctx_two );

 return exitcode;
}
