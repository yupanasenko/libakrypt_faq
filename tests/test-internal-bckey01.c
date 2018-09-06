 #include <ak_bckey.h>

 int main( void )
{
  struct bckey magma_key;
  int i, error = ak_error_ok;
  ak_uint32 key[8] = { 0x12345678, 0xabcdef0, 0x11223344, 0x55667788, 0xaabbccdd, 0xeeff0011, 0xa1a1a2a2, 0xa3a3a4a4 };

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

 /* выводим информацию */
  printf("key:\t");
  for( i = 0; i < 8; i++ ) printf("%08X", ((ak_uint32 *)magma_key.key.key.data)[i] );
  printf("\nmask:\t");
  for( i = 0; i < 8; i++ ) printf("%08X", ((ak_uint32 *)magma_key.key.mask.data)[i] );
  printf("\nreal:\t");
  for( i = 0; i < 8; i++ ) printf("%08X", ((ak_uint32 *)magma_key.key.key.data)[i] - ((ak_uint32 *)magma_key.key.mask.data)[i] );
  printf("\nicode:\t");
  for( i = 0; i < 8; i++ ) printf("%02X", ((ak_uint8 *)magma_key.key.icode.data)[i] );
  if( magma_key.key.check_icode( &magma_key.key ) == ak_true ) printf(" (Ok)\n");
   else printf(" (Wrong)\n");

  // осталось только реализовать шифрование )))

  ak_bckey_context_destroy( &magma_key );
  lab_exit: ak_libakrypt_destroy();
 return error;
}
