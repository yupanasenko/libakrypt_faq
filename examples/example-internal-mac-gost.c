/* ----------------------------------------------------------------------------------------------- *
   Тестовый пример, иллюстрирующий возможность использования класса compress для
   вычисления значения бесключевой функции хеширования

   Внимание: используются неэкспортируемые функции библиотеки
 * ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <ak_bckey.h>

 int main( void )
{
  int i = 0;

 /* константные значения ключей из ГОСТ Р 34.13-2015 */
  ak_uint8 keyAnnexA[32] = {
   0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
   0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

  ak_uint8 keyAnnexB[32] = {
   0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
   0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

  ak_uint32 inlong[16] = {
   0xbbaa9988, 0xffeeddcc, 0x55667700, 0x11223344, 0xcceeff0a, 0x8899aabb, 0x44556677, 0x00112233,
   0xeeff0a00, 0x99aabbcc, 0x55667788, 0x11223344, 0xff0a0011, 0xaabbccee, 0x66778899, 0x22334455 };

   ak_uint64 in_3413_2015_text[4] = {
                   0x92def06b3c130a59, 0xdb54c704f8189d20, 0x4a98fb2e67a8024c, 0x8912409b17b57e41 };

  ak_uint8 string[512], out[16];
  struct bckey Key;

  ak_libakrypt_create( ak_function_log_stderr );

 /* выводим данные, в соответствии с форматом принятом в ГОСТ 34.13-2015 */
  printf("Kuznechik test\n");
  for( i = 0; i < 4; i++ ) {
     ak_ptr_to_hexstr_static( inlong+4*i, 16, string, 512, ak_true );
     printf("p%d:  %s\n", i+1, string );
  }

 /* создаем и инициализируем ключ блочного алгоритма шифрования КУЗНЕЧИК */
  ak_bckey_create_kuznechik( &Key );
  ak_bckey_context_set_ptr( &Key, keyAnnexA, 32, ak_false );
                            /* ak_false => данные не копируются в контект ключа */

 /* вычисляем имитовставку. результат помещается в out */
  ak_bckey_context_mac_gost3413( &Key, inlong, 64, out );

 /* выводим результат */
  ak_ptr_to_hexstr_static( out, 16, string, 512, ak_true );
  printf("\nmac: %s\n", string );
  printf("MAC: 336f4d296059fbe3 (GOST example: highest 8 octets form 16)\n\n");

 /* уничтожаем ключевую информацию */
  ak_bckey_destroy( &Key );

 /* выводим данные, в соответствии с форматом принятом в ГОСТ 34.13-2015 */
  printf("Magma test\n");
  for( i = 0; i < 4; i++ ) {
     ak_ptr_to_hexstr_static( in_3413_2015_text+i, 8, string, 512, ak_true );
     printf("p%d:  %s\n", i+1, string );
  }

  /* создаем и инициализируем ключ блочного алгоритма шифрования MAGMA */
  ak_bckey_create_magma( &Key );
  ak_bckey_context_set_ptr( &Key, keyAnnexB, 32, ak_false );

  /* вычисляем имитовставку. результат помещается в out */
  ak_bckey_context_mac_gost3413( &Key, in_3413_2015_text, 32, out );

  /* выводим результат */
  ak_ptr_to_hexstr_static( out, 8, string, 512, ak_true );
  printf("\nmac: %s\n", string );
  printf("MAC: 154e7210 (GOST example: highest 4 octets form 8)\n\n");

  /* уничтожаем ключевую информацию */
  ak_bckey_destroy( &Key );

  ak_libakrypt_destroy();
}
