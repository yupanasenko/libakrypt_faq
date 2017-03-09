#include <stdio.h>
#include <libakrypt.h>
#include <ak_skey.h>
#include <ak_hash.h>
#include <ak_context_manager.h>

 void print_status( ak_context_manager manager )
{
  size_t i = 0;

  printf("size:  %lu (count: %lu)\n", manager->size, manager->count );
  printf("imask: %lx\n", manager->imask );
  for( i = 0; i < manager->size;i++ ) {
   if( manager->array[i] == NULL ) printf("%02lu: (null)\n", i);
  }
}

 int main( void )
{
 /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) {
   return ak_libakrypt_destroy();
  }

 struct context_manager mgr;
  ak_context_manager_create( &mgr, ak_random_new_lcg( ));
  print_status( &mgr );

  ak_context_manager_destroy( &mgr );
  print_status( &mgr );
 return ak_libakrypt_destroy();
}
