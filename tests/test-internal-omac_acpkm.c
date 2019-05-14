/* Пример, иллюстрирующий режим шифрования ctr_acpkm
   (на примере блочного шифра кузнечик).
   Используются неэкспортируемые функции библиотеки.

   test-internal-bckey02.c
*/
 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
 #include <ak_bckey.h>
 #define size1 (24)
 #define size2 (40)
 #define key_size1 (32)
 #define key_size2 (32)
 #define section_size1 (32)
 #define section_size2 (16)
 int main( void )
{
  struct bckey key1, key2;
  int i, error = ak_error_ok;
  ak_uint8 skey1[key_size1] = {
      0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
      0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

  ak_uint8 in1[size1] = {
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
      0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
  ak_uint8 out1[16];
  ak_uint8 out_check1[16] = {
      0x5E, 0x14, 0x43, 0x58, 0x8C, 0x64, 0x2A, 0xEB, 0x5E, 0x99, 0x2B, 0xB6, 0x47, 0x7F, 0x36, 0xB5 };

  ak_uint8 skey2[key_size2] = {
      0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
      0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

  ak_uint8 in2[size2] = {
      0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
      0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
      0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
      0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
  ak_uint8 out2[8];
  ak_uint8 out_check2[8] = {
      0x8E, 0xBB, 0x96, 0x54, 0xAD, 0x8D, 0x00, 0x34 };

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr ))
    return ak_libakrypt_destroy();

 /* создаем ключ алгоритма блочного шифрования */
  if(( error = ak_bckey_context_create_kuznechik( &key1 )) != ak_error_ok ) goto lab_exit;
  if(( error = ak_bckey_context_create_magma( &key2 )) != ak_error_ok ) goto lab_exit;

 /* присваиваем ключу заданное значение */
  if(( error = ak_bckey_context_set_key( &key1, skey1, key_size1, ak_true )) != ak_error_ok ) {
    ak_bckey_context_destroy( &key1 );
    goto lab_exit;
  }
 /* присваиваем ключу заданное значение */
  if(( error = ak_bckey_context_set_key( &key2, skey2, key_size2, ak_true )) != ak_error_ok ) {
    ak_bckey_context_destroy( &key2 );
    goto lab_exit;
  }

  printf("plain text for kuznechik\n");
  for( i = 0; i < size1; i++ ) printf("%02X", in1[i] );
  printf("\n");

 /* первый раз получаем хеш с помощью кузнечика*/
  ak_bckey_context_omac_acpkm( &key1, in1, size1, out1, section_size1, 96 );
  printf("hash sum using kuznechik\n");
  for( i = 0; i < key1.bsize; i++ ) printf("%02X", out1[i] );
  printf("\n");

  if( !memcmp( out1, out_check1, 16)) printf(" Ok\n");
    else { printf(" Wrong\n"); error = EXIT_FAILURE; goto lab_exit; }

  printf("plain text for magma\n");
  for( i = 0; i < size2; i++ ) printf("%02X", in2[i] );
  printf("\n");

 /* второй раз получаем хеш с помощью магмы*/
  ak_bckey_context_omac_acpkm( &key2, in2, size2, out2, section_size2, 80 );
  printf("hash sum using magma\n");
  for( i = 0; i < key2.bsize; i++ ) printf("%02X", out2[i] );
  printf("\n");

  if( !memcmp( out2, out_check2, 8)) printf(" Ok\n");
    else { printf(" Wrong\n"); error = EXIT_FAILURE; goto lab_exit; }

  ak_bckey_context_destroy( &key1 );
  ak_bckey_context_destroy( &key2 );
  lab_exit: ak_libakrypt_destroy();

  return error;
}
