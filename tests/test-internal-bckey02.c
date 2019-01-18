/* Пример, иллюстрирующий различные способы вызова режима гаммирования
   (на примере блочного шифра Магма).
   Используются неэкспортируемые функции библиотеки.

   test-internal-bckey02.c
*/
 #include <stdio.h>
 #include <string.h>
 #include <ak_bckey.h>
 #define size (67)

 int main( void )
{
  struct bckey magma_key;
  struct random generator;
  int i, error = ak_error_ok;
  ak_uint8 iv[4] = { 0x01, 0x02, 0x03, 0x04 }, in[size], out[size], out1[size];
  ak_uint32 key[8] = {
    0x12345678, 0xabcdef0, 0x11223344, 0x55667788,
    0xaabbccdd, 0xeeff0011, 0xa1a1a2a2, 0xa3a3a4a4
  };

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr ))
    return ak_libakrypt_destroy();

 /* создаем ключ алгоритма блочного шифрования */
  if(( error = ak_bckey_context_create_magma( &magma_key)) != ak_error_ok ) goto lab_exit;

 /* присваиваем ключу заданное значение */
  if(( error = ak_bckey_context_set_key( &magma_key, key, 32, ak_true )) != ak_error_ok ) {
    ak_bckey_context_destroy( &magma_key );
    goto lab_exit;
  }

 /* создаем массив случайных данных */
  ak_random_context_create_hashrnd_streebog256( &generator );
  ak_random_context_random( &generator, in, size );
  ak_random_context_destroy( &generator );
  printf("plain text\n");
  for( i = 0; i < size; i++ ) printf("%02X", in[i] );
  printf("\n");

 /* первый раз шифруем одним махом весь буффер */
  ak_bckey_context_xcrypt( &magma_key, in, out, size, iv, 4 );
  printf("cipher text\n");
  for( i = 0; i < size; i++ ) printf("%02X", out[i] );
  printf(" (one call)\n");

 /* второй раз шифруем фрагментами (длина которых кратна длине блока) */
  ak_bckey_context_xcrypt( &magma_key, in, out1, 16, iv, 4 );
  ak_bckey_context_xcrypt( &magma_key, in+16, out1+16, 16, NULL, 0 );
  ak_bckey_context_xcrypt( &magma_key, in+32, out1+32, size-32, NULL, 0 );
  printf("cipher text\n");
  for( i = 0; i < size; i++ ) printf("%02X", out1[i] );
  printf(" (some calls)\n");

  ak_bckey_context_destroy( &magma_key );
  lab_exit: ak_libakrypt_destroy();
 return memcmp( out, out1, size );
}
