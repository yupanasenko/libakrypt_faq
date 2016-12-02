 #include <stdio.h>
 #include <libakrypt.h>

 int main( void )
{
 int error = ak_error_ok;
 ak_key id = 0;
 char *str = NULL;
 ak_uint32 in[8] = /* исходный массив данных для шифрования */
  { 0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff, 0x01234567, 0x89abcdef, 0x6666aaaa, 0x1111ffff };
 ak_uint8 out[32], res[32];
 memset( out, 0, 32 );  memset( res, 0, 32 );

 /* инициализируем библиотеку */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) return ak_libakrypt_destroy();

 /* выводим исходный массив данных */
  printf("in:  %s\n", str = ak_ptr_to_hexstr( in, 32, ak_false )); free(str);

 /* создаем случайный ключ */
  id = ak_key_new_magma("new Magma key");
  printf("key\n number: %s\n description: %s\n", ak_key_get_number(id), ak_key_get_description(id));
  printf(" max size of encrypted/decrypted data: %u blocks (%u MB)\n", ak_key_get_resource(id),
                                                          (64*ak_key_get_resource(id))/(1024*1024));
 /* зашифровываем исходный массив данных */ 
  error = ak_key_encrypt_ecb( id, in, out, 32 );
  printf("encrypt: %s (code: %d)\n", str = ak_ptr_to_hexstr( out, 32, ak_false ), error ); free(str);

 /* расшифровываем данные и сравниваем с исходным массивом */
  ak_key_decrypt_ecb( id, out, res, 32 );
  printf("decrypt: %s", str = ak_ptr_to_hexstr( res, 32, ak_false )); free(str);
  if(memcmp( in, res, 32 )) printf(" is wrong\n");
   else printf(" is Ok\n");
  printf(" max size of encrypted/decrypted data: %u blocks (%u MB)\n", ak_key_get_resource(id),
                                                          (64*ak_key_get_resource(id))/(1024*1024));

 return ak_libakrypt_destroy(); // деактивируем криптографические механизмы
}
