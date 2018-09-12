/* ----------------------------------------------------------------------------------------------- *
   Пример, иллюстрирующий внутренние механизмы
   создания и удаления элементов структуры управления контекстами
   Внимание: используются неэкспортируемые функции библиотеки

 * ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <stdlib.h>
 #include <libakrypt.h>
 #include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
/* Пользовательская функция освобождения памяти - возвращает NULL */
 ak_pointer myfree( ak_pointer ptr ) { free( ptr ); return NULL; }

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
  ak_pointer ptr = NULL;
  ak_context_node node = NULL;

 /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
    return ak_libakrypt_destroy();

 /* простой тест на создание/удаление классов библиотеки */
  ak_context_node_delete(
    ak_context_node_new( ak_buffer_new_str("Be Buffer Is Cool"), 0x10,
                                 undefined_engine, "some buffer description", ak_buffer_delete ));

 /* теперь пример создания/удаления произвольного фрагмента памяти
    с пользовательской функцией освобождения памяти */

   ak_context_node_delete( node = ak_context_node_new( ptr = malloc( 128 ), 128,
                                          undefined_engine, "memory block description", myfree ));

  return ak_libakrypt_destroy();
}

/* ----------------------------------------------------------------------------------------------- */
