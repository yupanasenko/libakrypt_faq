/* ----------------------------------------------------------------------------------------------- *
   Пример, иллюстрирующий внутренние механизмы работы структуры управления контекстами
   Внимание: используются неэкспортируемые функции библиотеки

 * ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <stdlib.h>
 #include <ak_random.h>
 #include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
/* вывод информации о состоянии структуры управления контекстами */
 void print_context_managet_status( ak_context_manager , ak_handle , size_t );

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
  ak_oid oid = NULL;
  struct context_manager manager;
  ak_handle handle = ak_error_wrong_handle;

  ak_handle delarray[100]; /* массив дескрипторов, которые будут уничтожаться */
  size_t i, iternum = 0, delcount = 0; /* счетчик числа удаляемых дескрипторов */

 /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) {
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }

 /* cоздаем структуру для хранения контекстов пользователя */
  if( ak_context_manager_create( &manager ) != ak_error_ok ) {
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }

 /* имитируем действия по заполнению структуры управления контекстами */
  do {
    /* помещаем в структуру контекст буффера с заданным значением и описанием */
       ak_pointer ctx = malloc( sizeof( struct random ));
       if( ctx == NULL ) continue;

       if( oid == NULL ) oid = ak_oid_context_find_by_engine( random_generator );
         else
           if(( oid = ak_oid_context_findnext_by_engine( oid, random_generator )) == NULL )
             oid = ak_oid_context_find_by_engine( random_generator );
       if( oid == NULL ) break;

       ak_random_context_create_oid( ctx, oid );
       if(( handle = ak_context_manager_add_node(
                      &manager,
                      ctx,
                      random_generator,
                      "description++"
       )) == ak_error_wrong_handle ) ak_random_context_delete( ctx );

    /* запоминаем некоторые значения дескрипторов */
       if(( delcount < 100 ) && ( !(handle%7) )) {
          delarray[delcount] = handle;
          delcount++;
       }

    /* выводим текущее значение структуры и декриптора для некоторых шагов цикла */
       if( !(++iternum%33) )
         print_context_managet_status( &manager, handle, iternum );

  } while( handle != ak_error_wrong_handle );


  ak_error_set_value( ak_error_ok );

 /* теперь имитируем действия по удалению контекстов в процессе работы  */
  printf("list of deleted handles:\n");
  for( i = 0; i < delcount; i++ ) {
     ak_context_manager_delete_node( &manager, delarray[i] );
     printf("%u ", (unsigned int) delarray[i] );
  }
  printf("\n");

  for( i = 0; i < 10; i++ ) {
     ak_context_node ctx = ( ak_context_node )manager.array[i];
     if( ctx != NULL ) {
       printf("idx: %4u -> name: %s (oid %s)\n",
          (unsigned int)i, ctx->oid->names[0], ctx->oid->id );
      } else printf("idx: %4u -> null\n", (unsigned int) i);
  }

 /* полностью удаляем структуру и хранящиеся в ней объекты */
  ak_context_manager_destroy( &manager );
  ak_libakrypt_destroy();

 return EXIT_SUCCESS;
}

/* ----------------------------------------------------------------------------------------------- */
 void print_context_managet_status( ak_context_manager manager, ak_handle handle, size_t iter )
{
  if( manager == NULL ) printf("null\n");
   else {
     printf("iter: %4u -> [manager size: %4u, current handle: %016llx\n",
            (unsigned int)iter, (unsigned int)manager->size, (unsigned long long int)handle );
   }
}

/* ----------------------------------------------------------------------------------------------- */
