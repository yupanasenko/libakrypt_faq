 #include <stdio.h>
 #include <libakrypt.h>

 int main( void )
{
 ak_hash ctx = NULL; /* определяем контекст */
 ak_uint8 data[12] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };

 /* инициализируем библиотеку */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) return ak_libakrypt_destroy();

 /* создаем контекст функции хеширования */
  if(( ctx = ak_hash_new_streebog256()) == NULL ) {
    ak_error_message( ak_error_get_value(), "wrong creation of hash context", __func__ );
  } else {
           char *str = NULL;
           /* вычисляем хеш-код и помещаем его в буффер */
           ak_buffer buff = ak_hash_data( ctx, data, sizeof(data), NULL );
           printf(" length (in bytes): %lu\n", ak_hash_get_code_size(ctx));
           printf(" code: %s\n", ak_buffer_to_hexstr(buff));

           /* теперь удаляем память */
           free( str );
           buff = ak_buffer_delete( buff );
           ctx = ak_hash_delete( ctx );
         }
 return ak_libakrypt_destroy(); /* останавливаем библиотеку и выходим */
}
