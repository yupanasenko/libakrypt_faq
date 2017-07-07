/* ----------------------------------------------------------------------------------------------- *
   Пример, иллюстрирующий внутренние механизмы работы структуры управления контекстами
   Внимание: используются неэкспортируемые функции библиотеки

 * ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <stdlib.h>
 #include <libakrypt.h>

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_random.h>
 #include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
  size_t i = 0;
//  ak_context_node node = NULL;
  ak_handle handle = ak_error_wrong_handle;

 /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) {
    return ak_libakrypt_destroy();
  }

//  ak_context_node_delete(
//    ak_context_node_new( ak_buffer_new_str("Be Buffer Is Cool"), 10,
//                                   undefined_engine, "undefined engine blala", ak_buffer_delete ));

  return ak_libakrypt_destroy();
}
/* ----------------------------------------------------------------------------------------------- */
