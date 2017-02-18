 #include <stdio.h>
 #include <libakrypt.h>

 #define data_size 137

 int main( void )
{
  ak_uint8 *ptr = NULL;
  char *str = NULL;
  size_t offset = 0, tail = data_size;
  ak_hash ctx = NULL;
  ak_update upd = NULL;       /* контекст структуры сжатия данных */
  ak_uint8 data[data_size];      /* данные для хеширования */
  ak_random generator = NULL; /* псевдослучайный генератор */
  ak_buffer result = NULL;    /* буффер для результов хеширования */

 /* Инициализируем библиотеку */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
    return ak_libakrypt_destroy();

 /* Определяем данные для хеширования */
  memset( data, 0, data_size );
  data[0] = 0xa; data[data_size-1] = 0xf;

 /* Создаем контекст сжатия данных с помощью функции хеширования ГОСТ Р 34.11-94 */
  upd = ak_update_new_hash( ctx = ak_hash_new_gosthash94( ak_oids_find_by_id( "1.2.643.2.2.30.1" )));

 /* Создаем генератор псевдослучайных чисел */
  generator = ak_random_new_lcg();

 /**/
  while( tail > 32 ) {
     size_t len = ak_random_uint8( generator )%32;
     printf(" %s\n", str = ak_ptr_to_hexstr( data+offset, len, ak_false )); free(str);
     ak_update_update( upd, data+offset, len );
     offset += len; tail -= len;
  }
  printf(" %s\n", str = ak_ptr_to_hexstr( data+offset, tail, ak_false )); free(str);
//  result = ak_update_finalize( upd, data+offset, tail, NULL );
//  printf(" small parts hash: %s\n", str = ak_buffer_to_hexstr( result ));
//  free( str ); result = ak_buffer_delete( result );

  generator = ak_random_delete( generator );
  upd = ak_update_delete( upd );
 return ak_libakrypt_destroy();
}

/*
  offset = 0; tail = data_size;

  ak_hash_data( ctx, ak_buffer_get_ptr(data), ak_buffer_get_size(data), out );
  printf(" ak_hash_data():\n %s\n", str = ak_ptr_to_hexstr( out, 32, ak_false ));
  free( str );

  memset( out, 0, 32 );
  upd = ak_update_new_hash( ctx );
  ptr = ak_buffer_get_ptr(data);
//  ak_update_update( upd, ak_buffer_get_ptr(data), 128 );
  result = ak_update_finalize( upd, (char *)ak_buffer_get_ptr(data), 65571, NULL );
  printf(" one chunck:\n %s\n", str = ak_buffer_to_hexstr( result ));
  free( str );
  result = ak_buffer_delete( result );

*/

/*
  data = ak_buffer_new_random( generator = ak_random_new_lcg(), 171 );


   ptr = ( char *) ak_buffer_get_ptr( data );
  tail = ak_buffer_get_size( data );
  while( tail > 32 ) {
    offset = ak_random_uint8( generator )%32;
    ak_update_update( upd, ptr, offset );
    ptr += offset; tail -= offset;
  }
  result = ak_update_finalize( upd, ptr, 0, NULL );
  printf(" ak_hash_data(): %s\n", str = ak_buffer_to_hexstr( data ));
  free( str ); result = ak_buffer_delete( result );


  result = ak_hash_data( ctx, ak_buffer_get_ptr( data ), ak_buffer_get_size( data ), NULL );
  printf(" ak_hash_data(): %s\n", str = ak_buffer_to_hexstr( result ));
  free( str ); result = ak_buffer_delete( result );

  upd = ak_update_delete( upd );
  data = ak_buffer_delete( data );
  generator = ak_random_delete( generator );
*/
