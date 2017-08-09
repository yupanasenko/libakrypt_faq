 #include <stdio.h>
 #include <libakrypt.h>

 int main( void )
{
 /* определяем дескриптор и инициализируем его */
  ak_handle handle = ak_error_wrong_handle;
 /* определяем данные для хэширования */
  ak_uint8 data[12] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };

 /* инициализируем библиотеку */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
    return ak_libakrypt_destroy();

 /* создаем контекст функции хеширования */
  if(( handle = ak_hash_new_gosthash94(
                ak_oid_find_by_id( "1.2.643.2.2.30.1" ) )) == ak_error_wrong_handle ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong descriptor creation");
    return ak_libakrypt_destroy();
  }

  // ожидаемое значение длиины хэшкода
  // действительное значение (через буффер)
  // + вызов чере статическую память


  printf("block size: %d, code size: %d\n",
     (int) ak_hash_get_block_size( handle ), (int) ak_hash_get_code_size( handle ));

//           char *str = NULL;
//           /* вычисляем хеш-код и помещаем его в буффер */
//           ak_buffer buff = ak_hash_data( ctx, data, sizeof(data), NULL );
//           printf(" length (in bytes): %lu\n", ak_hash_get_code_size(ctx));
//           printf(" code: %s\n", str = ak_buffer_to_hexstr(buff));

//           /* теперь удаляем память */
//           free( str );
//           buff = ak_buffer_delete( buff );
//           ctx = ak_hash_delete( ctx );

 return ak_libakrypt_destroy(); /* останавливаем библиотеку и выходим */
}
