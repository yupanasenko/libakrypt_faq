 #include <time.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <ak_bckey.h>
 #include <ak_key_manager.h>
 #include <ak_asn1_keys.h>

 int main( void )
{
  struct bckey bkey;
  char filename[1024];
  struct key_manager km;
  ak_uint8 testkey[32] = {
    0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x38 };

 /* инициализируем библиотеку */
  ak_log_set_level( ak_log_maximum );
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* создаем менеджер ключевой информации */
  printf("create manager: %dk\n", ak_key_manager_context_create_in_directory( &km, NULL ));

 /* создаем какой-то ключ и экпортируем его в файл (в der-кодировке) */
  printf("create key: %dk\n", ak_bckey_context_create_magma( &bkey ));
  ak_bckey_context_set_key( &bkey, testkey, sizeof( testkey ));
  ak_key_context_export_to_file_with_password( &bkey, block_cipher,
                   "password", 8, "user key name", filename, sizeof( filename ), asn1_der_format );
  printf("key saved to %s file\n", filename );

 /* добавляем ключ в ключевое хранилище */
  km.add_container( &km, filename, symmetric_key_content );

 /* удаляем за собой */
  ak_bckey_context_destroy( &bkey );
  ak_key_manager_context_destroy( &km );
  ak_libakrypt_destroy();

 return EXIT_SUCCESS;
}
