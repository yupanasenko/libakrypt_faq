/* ----------------------------------------------------------------------------------------------- *
   Пример, иллюстрирующий внутренние механизмы работы структуры управления контекстами
   Внимание: используются неэкспортируемые функции библиотеки

 * ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <stdlib.h>
 #include <libakrypt.h>
 #include <ak_random.h>
 #include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
/* вывод информации о состоянии структуры управления контекстами */
 void print_context_managet_status( ak_context_manager , ak_handle , size_t );

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
  ak_buffer buffer = NULL;
  struct context_manager manager;
  ak_handle handle = ak_error_wrong_handle;

  ak_handle delarray[100]; /* массив дескрипторов, которые будут уничтожаться */
  size_t i, iternum = 0, delcount = 0; /* счетчик числа удаляемых дескрипторов */

 /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) {
    return ak_libakrypt_destroy();
  }

 /* cоздаем структуру для хранения контекстов пользователя
    в процессе создания функция malloc вызывается 2 раза:
    (один раз при создании генератора и один раз для массива указателей на контексты) */
  if( ak_context_manager_create( &manager ) != ak_error_ok )
    return ak_libakrypt_destroy();

 /* имитируем действия по заполнению структуры управления контекстами */
  do {
    /* помещаем в структуру контекст буффера с заданным значением и описанием */
       if(( handle = ak_context_manager_add_node(
                      &manager,
                      buffer = ak_buffer_new_str("string in buffer"),
                      undefined_engine,
                      NULL, //"buffer description", <- для NULL здесь unconditional jump - разобраться
                      ak_buffer_delete
    /* удаляем буффер, которому не хватило места в структуре */
       )) == ak_error_wrong_handle ) ak_buffer_delete( buffer );

    /* запоминаем некоторые значение дескриптора */
       if(( delcount < 100 ) && ( !(handle%13) )) {
          delarray[delcount] = handle;
          delcount++;
       }

    /* выводим текущее значение структуры и декриптора для некоторых шагов цикла */
       if( !(++iternum%32) )
         print_context_managet_status( &manager, handle, iternum );

  } while( handle != ak_error_wrong_handle );

 /* теперь имитируем действия по удалению контекстов в процессе работы  */
  printf("list of deleted handles:\n");
  for( i = 0; i < delcount; i++ ) {
     ak_context_manager_delete_node( &manager, delarray[i] );
     printf("%lu ", delarray[i] );
  }
  printf("\n");
  print_context_managet_status( &manager, 0, 0 );

 /* полностью удаляем структуру и хранящиеся в ней объекты */
  ak_context_manager_destroy( &manager );

 return ak_libakrypt_destroy();
}

/* ----------------------------------------------------------------------------------------------- */
 void print_context_managet_status( ak_context_manager manager, ak_handle handle, size_t iter )
{
  if( manager == NULL ) printf("null\n");
   else {
     printf("iter: %lu ->address: %016lx, array address: %016lx [size: %ld, handle: %016lx]\n",
                     iter, (ak_uint64) manager, (ak_uint64)manager->array, manager->size, handle );
  }
}

/* ----------------------------------------------------------------------------------------------- */
