/* Пример, иллюстрирующий создание и удаление структур для хранения контекстов.
   Данные структуры используются менеджером контекстов для организации доступа
   пользователя к данным.
   Внимание! В примере используются неэкспортируемые функции библиотеки.

   test-internal-context-node.c
*/
 #include <stdio.h>
 #include <stdlib.h>
 #include <ak_bckey.h>
 #include <ak_context_manager.h>

 static ak_uint32 constkey[8] = {
    0x12345678, 0xabcdef0, 0x11223344, 0x55667788,
    0xaabbccdd, 0xeeff0011, 0xa1a1a2a2, 0xa3a3a4a4
 };

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
  ak_bckey_context_create_magma( bkey );
  ak_bckey_context_set_key( bkey, constkey, 32, ak_true );
 return bkey;
}

 int main( void )
{
  ak_context_node node;
  ak_uint8 databuffer[1024], str[128];

  ak_libakrypt_create( ak_function_log_stderr );

   /* 1. первый тест на создание */
    if(( node = ak_context_node_new( create_random(),
                                       123, random_generator, "random_generator" )) != NULL ) {
      printf("\ncreated: %s (OID: %s)\n", node->oid->name, node->oid->id );
      printf("user description: %s\n", ak_buffer_get_str( &node->description ));
     /* имитируем работу генератора */
      printf("work result: %d ", ak_random_context_random( node->ctx, databuffer, 1024 ));
      ak_ptr_to_hexstr_static( databuffer, 32, str, 128, ak_false );
      printf("[%s]\n", str );
     /* уничтожаем все */
      ak_context_node_delete( node );
    }

   /* 2. тест на использование блочного шифра */
    if(( node = ak_context_node_new( create_bckey(),
                                       124, block_cipher, "block_cipher" )) != NULL ) {
      printf("\ncreated: %s (OID: %s)\n", node->oid->name, node->oid->id );
      printf("user description: %s\n", ak_buffer_get_str( &node->description ));
     /* имитируем работу */
      ak_ptr_to_hexstr_static( databuffer, 32, str, 128, ak_false );
      printf("plain text:     %s\n", str );
      ak_bckey_context_xcrypt( node->ctx, databuffer, databuffer, 32, /* синхропосылка */
                                                                      constkey, 4 );
      ak_ptr_to_hexstr_static( databuffer, 32, str, 128, ak_false );
      printf("encrypted text: %s\n", str );
      ak_bckey_context_xcrypt( node->ctx, databuffer, databuffer, 32, /* синхропосылка */
                                                                      constkey, 4 );
      ak_ptr_to_hexstr_static( databuffer, 32, str, 128, ak_false );
      printf("plain text:     %s\n\n", str );
     /* уничтожаем все */
      ak_context_node_delete( node );
    }

   /* 3. тест на некорректные данные
      передаем явный мусор как контекст функции hmac */
    if(( node = ak_context_node_new( databuffer,
                             125, hmac_function, "digital sign create function" )) != NULL ) {
      printf("unexpected success\n");
      ak_error_set_value( ak_error_undefined_value );
    } {
        printf("correct work with wrong context pointer\n");
        ak_error_set_value( ak_error_ok );
      }

 return ak_libakrypt_destroy();
}
