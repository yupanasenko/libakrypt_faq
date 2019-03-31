/* Пример иллюстрирует множество внутренних значений ключа блочного алгоритма шифрования.
   Для иллюстрации используется прямой доступ к данным и методом класса bckey.
   Внимание! Используются неэкспортируемые функции.

   test-internal-bckey01.c
*/
 #include <stdio.h>
 #include <ak_bckey.h>

 int main( void )
{
  size_t i = 0;
  struct bckey skey;
  int error = ak_error_ok;
  ak_uint8 const_key[32] = {
    0x12, 0x34, 0x56, 0x78, 0x0a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0xa1, 0xa1, 0xa2, 0xa2, 0xa3, 0xa3, 0xa4, 0xa4 };

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* создаем ключ алгоритма блочного шифрования */
  if(( error = ak_bckey_context_create_kuznechik( &skey)) != ak_error_ok ) {
    ak_libakrypt_destroy( );
    return error;
  }

 /* присваиваем ключу заданное значение
    значение ak_true в вызове функции означает, что значение ключа копируется в контекст ключа */
  if(( error = ak_bckey_context_set_key( &skey, const_key, 32, ak_true )) != ak_error_ok )
    goto lab_exit;

 /* выводим информацию */
  printf("key:\t");
  for( i = 0; i < skey.key.key.size; i++ ) printf("%02X", ((ak_uint8 *)skey.key.key.data)[i] );
  printf("\nmask:\t");
  for( i = 0; i < skey.key.key.size; i++ ) printf("%02X", ((ak_uint8 *)skey.key.mask.data)[i] );

  printf("\nicode:\t");
  for( i = 0; i < skey.key.icode.size; i++ ) printf("%02X", ((ak_uint8 *)skey.key.icode.data)[i] );
  if( skey.key.check_icode( &skey.key ) == ak_true ) printf(" (Ok)\n");
   else printf(" (Wrong)\n");

  skey.key.unmask( &skey.key ); /* снимаем маску */
  printf("\nreal:\t");
  for( i = 0; i < skey.key.key.size; i++ ) printf("%02X", ((ak_uint8 *)skey.key.key.data)[i] );
  skey.key.set_mask( &skey.key );
  printf("\n");

 /* выходим */
  lab_exit:
    ak_bckey_context_destroy( &skey );
    ak_libakrypt_destroy();
 return error;
}
