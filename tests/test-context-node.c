/* Пример, иллюстрирующий создание и удаление структур для хранения контекстов.
   Данные структуры используются менеджером контекстов для организации доступа
   пользователя к данным.
   Внимание! В примере используются неэкспортируемые функции библиотеки.

   test-context-node.c
*/
 #include <stdio.h>
 #include <stdlib.h>
 #include <ak_bckey.h>
 #include <ak_context_manager.h>

 static ak_uint8 key[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

 /* очень короткая функция создания контекста генератора */
 ak_pointer create_random( void )
{
  ak_random rnd = malloc( sizeof( struct random ));
  ak_random_context_create_lcg( rnd );
 return rnd;
}

 /* очень короткая функция создания контекста блочного шифра */
 ak_pointer create_bckey( void )
{
  ak_bckey bkey = malloc( sizeof( struct bckey ));
  ak_bckey_context_create_kuznechik( bkey );
  ak_bckey_context_set_key( bkey, key, 32 );
 return bkey;
}

 int main( void )
{
  ak_context_node node;
  ak_uint8 databuffer[128];
  int result = EXIT_SUCCESS;

  ak_libakrypt_create( ak_function_log_stderr );

   /* 1. первый тест на создание */
    if(( node = ak_context_node_new( create_random(),
                                123, random_generator, "linear congruence generator" )) != NULL ) {
      printf("\ncreated: %s (OID: %s)\n", node->oid->names[0], node->oid->id );
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
    if(( node = ak_context_node_new( create_bckey(),
                                       124, block_cipher, "block_cipher" )) != NULL ) {
      printf("\ncreated: %s (OID: %s)\n", node->oid->names[0], node->oid->id );
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
    if(( node = ak_context_node_new( databuffer,
                             125, hmac_function, "digital sign create function" )) != NULL ) {
      printf("unexpected success\n");
      ak_error_set_value( ak_error_undefined_value );
      result = EXIT_FAILURE;
    } {
        printf("correct work with wrong context pointer\n");
        ak_error_set_value( ak_error_ok );
      }

  ak_libakrypt_destroy();

 return result;
}
