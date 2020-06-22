/* Пример, иллюстрирующий создание и удаление структур для хранения контекстов.
   Данные структуры используются менеджером контекстов для организации доступа
   пользователя к данным.
   Внимание! В примере используются неэкспортируемые функции библиотеки.

   test-context-node.c
*/
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <ak_bckey.h>
 #include <ak_context_manager.h>

 static ak_uint8 key[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

 int main( void )
{
  ak_oid oid = NULL;
  ak_pointer ctx = NULL;
  ak_context_node node;
  ak_uint8 databuffer[128];
  int result = EXIT_SUCCESS;

  ak_libakrypt_create( ak_function_log_stderr );

   /* 1. первый тест на создание */
    oid = ak_oid_context_find_by_name("lcg");
    if(( node = ak_context_node_new( ak_oid_context_new_object( oid ),
                       123, oid, strdup( "linear congruence generator" ))) != NULL ) {
      printf("\ncreated: %s (OID: %s)\n", node->oid->info.name[0], node->oid->info.id[0] );
      printf("user description: %s\n", node->description );
     /* имитируем работу генератора */
      printf("work result: %d ",
                           ak_random_context_random( node->ctx, databuffer, sizeof( databuffer )));
      printf("[%s]\n", ak_ptr_to_hexstr( databuffer, 32, ak_false ));
     /* уничтожаем все */
      ak_context_node_delete( node );
    }
    if( ak_error_get_value() != ak_error_ok ) result = EXIT_FAILURE;

   /* 2. тест на использование блочного шифра */
    ctx = ak_oid_context_new_object( oid = ak_oid_context_find_by_name( "kuznechik" ));
    ak_bckey_context_set_key( ctx, key, 32 );
    if(( node = ak_context_node_new( ctx, 124, oid, strdup( "block_cipher" ))) != NULL ) {
      printf("\ncreated: %s (OID: %s)\n", node->oid->info.name[0], node->oid->info.id[0] );
      printf("user description: %s\n", node->description );
     /* имитируем работу */
      printf("plain text:     %s\n", ak_ptr_to_hexstr( databuffer, 32, ak_false ));
      ak_bckey_context_ctr( node->ctx, databuffer, databuffer, 32, /* синхропосылка */
                                                                      key, 8 );
      printf("encrypted text: %s\n", ak_ptr_to_hexstr( databuffer, 32, ak_false ));
      ak_bckey_context_ctr( node->ctx, databuffer, databuffer, 32, /* синхропосылка */
                                                                      key, 8 );
      printf("plain text:     %s\n\n", ak_ptr_to_hexstr( databuffer, 32, ak_false ));
     /* уничтожаем все */
      ak_context_node_delete( node );
    }
    if( ak_error_get_value() != ak_error_ok ) result = EXIT_FAILURE;

   /* 3. тест на некорректные данные
      передаем явный мусор как контекст функции hmac */
    if(( node = ak_context_node_new( databuffer, 125, oid, NULL )) != NULL ) {
      printf("unexpected success\n");
      ak_error_set_value( ak_error_undefined_value );
      result = EXIT_FAILURE;
    }
      {
        printf("correct work with wrong context pointer\n");
        ak_error_set_value( ak_error_ok );
      }

  ak_libakrypt_destroy();

 return result;
}
