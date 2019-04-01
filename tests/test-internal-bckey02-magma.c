/* Пример, иллюстрирующий зашифрование одного блока информации.
   (на примере блочного шифра Кузнечик).
   Внимание! Используются неэкспортируемые функции библиотеки.

   test-internal-bckey02.c
*/
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <ak_bckey.h>

 int main( void )
{
  struct bckey key;
  ak_uint8 out[32];
  int i, result = EXIT_SUCCESS, error = ak_error_ok;

  ak_uint8 in[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
  ak_uint8 outin[32] = {
    0x3D, 0xAB, 0x63, 0xA8, 0x56, 0x1C, 0x4C, 0x70, 0xF9, 0x15, 0x9F, 0xFE, 0xC6, 0x9C, 0x07, 0xCA,
    0x4D, 0x2E, 0xE0, 0xFA, 0x73, 0x3B, 0xED, 0x07, 0x95, 0x4B, 0x95, 0x87, 0x50, 0x8C, 0x63, 0xBD };

  ak_uint8 const_key[32] = {
    0x12, 0x34, 0x56, 0x78, 0x0a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0xa1, 0xa1, 0xa2, 0xa2, 0xa3, 0xa3, 0xa4, 0xa4 };

 /* 1. инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* 2. создаем ключ алгоритма блочного шифрования */
  if( ak_bckey_context_create_magma( &key) != ak_error_ok ) {
    ak_libakrypt_destroy();
    return EXIT_FAILURE;
  }

 /* 3. присваиваем ключу заданное значение */
  if(( error = ak_bckey_context_set_key( &key, const_key, 32, ak_true )) != ak_error_ok ) {
    result = EXIT_FAILURE;
    goto lab_exit;
  }

 /* 4. зашифровываем данные */
   if( ak_bckey_context_encrypt_ecb( &key, in, out, sizeof( in )) == ak_error_ok )
     printf("encryption of four blocks is Ok\n");
    else printf("encryption of four blocks is wrong\n");

   for( i = 0; i < 16; i++ ) { printf(" %02X", out[i] ); } printf("\n");
   for( i = 16; i < 32; i++ ) { printf(" %02X", out[i] ); }
   if( !memcmp( out, outin, sizeof( out ))) printf(" Ok\n");
     else { printf(" Wrong\n"); result = EXIT_FAILURE; goto lab_exit; }

 /* 4. расшифровываем данные */
   if( ak_bckey_context_decrypt_ecb( &key, outin, out, sizeof( outin )) == ak_error_ok )
     printf("decryption of four blocks is Ok\n");
    else printf("decryption of four blocks is wrong\n");

   for( i = 0; i < 16; i++ ) { printf(" %02X", out[i] ); } printf("\n");
   for( i = 16; i < 32; i++ ) { printf(" %02X", out[i] ); }
   if( !memcmp( out, in, sizeof( out ))) printf(" Ok\n");
     else { printf(" Wrong\n"); result = EXIT_FAILURE; goto lab_exit; }

 /* завершаем работу */
  lab_exit:
   ak_bckey_context_destroy( &key );
   ak_libakrypt_destroy();

 return result;
}
