/* Тестовый пример, иллюстрирующий использование внутренней структуры класса hash.
   Основное внимание стоит уделить функции test_hash_ptr().
   Пример использует неэкспортируемые функции.

   test-hash01a.c
*/

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <ak_hash.h>

/* основная программа */
 int main( void )
{
  const char *str = NULL;
  struct hash ctx_one;    /* объект, размещаемый в статической памяти (стеке) */
  int error = ak_error_ok, exitcode = EXIT_FAILURE;
  ak_uint8 out[32],
           some_pointer[7] = { 0, 1, 2, 3, 4, 5, 6 }; /* данные для хеширования */

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* статический объект существует, но он требует инициализации */
  if(( error = ak_hash_context_create_streebog256( &ctx_one )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect initialization of hash context" );
    goto exit_label;
  }

 /* вычисляем хеш-код от заданной области памяти (используя статический объект) */
  error = ak_hash_context_ptr( &ctx_one,
                          some_pointer, sizeof( some_pointer ), out, sizeof( out ));
  printf("hash [1]: %s (exit code: %d) ",
                    str = ak_ptr_to_hexstr( out, sizeof( out ), ak_false ), error );

 /* сравниваем полученный результат с ожидаемым */
  if( !strncmp( str,
       "c087bad4c0fdc5622873294b5d9c3b790a9dc55fb29b1758d5154adc2310f189", 32 )) {
    printf("Ok\n");
    exitcode = EXIT_SUCCESS;
  } else printf("Wrong\n");

  exit_label: /* конец рабочего примера */
   /* уничтожаем статический объект */
    ak_hash_context_destroy( &ctx_one );
   /* завершаем библиотеку */
    ak_libakrypt_destroy();

 return exitcode;
}
