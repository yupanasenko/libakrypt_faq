/* Пример, иллюстрирующий различные способы вызова режима гаммирования
   (на примере блочного шифра Кузнечик).
   Внимание! Используются неэкспортируемые функции библиотеки.

   test-internal-bckey02.c
*/
 #include <stdio.h>
 #include <string.h>
 #include <ak_bckey.h>
 #define size (67)

 int main( void )
{
  struct bckey key;
  int i, error = ak_error_ok;
  ak_uint8 iv[8] = { 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04 },
           in[size], out[size], out1[size];
  ak_uint8 const_key[32] = {
    0x12, 0x34, 0x56, 0x78, 0x0a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0xa1, 0xa1, 0xa2, 0xa2, 0xa3, 0xa3, 0xa4, 0xa4 };

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* создаем ключ алгоритма блочного шифрования */
  if(( error = ak_bckey_context_create_kuznechik( &key)) != ak_error_ok ) {
    ak_libakrypt_destroy( );
    return error;
  }

 /* присваиваем ключу заданное значение
    ak_true в вызове функции означает, что значение ключа копируется в контекст ключа */
  if(( error = ak_bckey_context_set_key( &key, const_key, 32, ak_true )) != ak_error_ok )
    goto lab_exit;

 /* создаем массив случайных данных (одинаковый для всех архитектур) */
  for( i = 0; i < size; i++ ) in[i] = (ak_uint8)( 3 + 113*i );
  printf("plain text:\n ");
  for( i = 0; i < size; i++ ) printf("%02X", in[i] );
  printf("\n");

 /* первый раз шифруем одним махом весь буффер */
  memset( out, 0, size ); /* обнуляем шифртекст */
  ak_bckey_context_ctr( &key, in, out, size, iv, sizeof( iv ));
  printf("cipher text:\n ");
  for( i = 0; i < size; i++ ) printf("%02X", out[i] );
  printf(" (one call)\n");

 /* второй раз шифруем фрагментами (длина которых кратна длине блока) */
  ak_bckey_context_ctr( &key, in, out1, 16, iv, sizeof( iv ));
  ak_bckey_context_ctr( &key, in+16, out1+16, 16, NULL, 0 );
  ak_bckey_context_ctr( &key, in+32, out1+32, size-32, NULL, 0 );
  printf("cipher text:\n ");
  for( i = 0; i < size; i++ ) printf("%02X", out1[i] );
  printf(" (some calls)\n");

  lab_exit:
   ak_bckey_context_destroy( &key );
   ak_libakrypt_destroy();

 return memcmp( out, out1, size );
}
