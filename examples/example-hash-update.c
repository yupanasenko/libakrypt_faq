 #include <stdio.h>
 #include <libakrypt.h>

 #define data_size 23715

 int main( void )
{
  char *str = NULL;
  size_t offset = 0, tail = data_size;
  ak_hash ctx = NULL;
  ak_update upd = NULL;       /* контекст структуры сжатия данных */
  ak_uint8 data[data_size];   /* данные для хеширования */
  ak_random generator = NULL; /* псевдослучайный генератор */
  ak_buffer result = NULL;    /* буффер для результов хеширования */

 /* Инициализируем библиотеку */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
    return ak_libakrypt_destroy();

 /* Определяем данные для хеширования */
  memset( data, 0, data_size );
  data[0] = 0xa; data[data_size-1] = 0xf;

 /* Создаем контекст сжатия данных с помощью функции хеширования ГОСТ Р 34.11-94 */
                           /* здесь можно использовать контекст любой из         */
                           /* функций хеширования, реализованных в библиотеке    */
  upd = ak_update_new_hash( ctx = ak_hash_new_gosthash94( ak_oids_find_by_id( "1.2.643.2.2.30.1" )));

 /* Создаем генератор псевдослучайных чисел */
  generator = ak_random_new_lcg();

 /* Нарезаем входные данные на фрагменты длины, меньшей чем длина обрабатываемого блока */
  offset = 0; tail = data_size; /* устанавливаем счетчики в исходное положение */
  ak_update_clean( upd ); /* очищаем контекст структуры сжатия данных */
  while( tail > ak_hash_get_block_size( ctx )) {
     ak_uint8 len = ak_random_uint8( generator )%ak_hash_get_block_size( ctx );
     ak_update_update( upd, data+offset, len );
     offset += len; tail -= len;
  }
  result = ak_update_finalize( upd, data+offset, tail, NULL );
  printf(" small parts:    %s\n", str = ak_buffer_to_hexstr( result ));
  free( str ); result = ak_buffer_delete( result );

 /* Теперь повторяем эксперимент, но с фрагментами большой длины */
  offset = 0; tail = data_size; /* устанавливаем счетчики в исходное положение */
  ak_update_clean( upd ); /* обязательно очищаем контекст структуры сжатия данных */
  while( tail > 32 ) {
     size_t len = ( size_t ) ak_random_uint64( generator )%(16*ak_hash_get_block_size( ctx ));
     if( len > tail ) continue;
     ak_update_update( upd, data+offset, len );
     offset += len; tail -= len;
  }
  result = ak_update_finalize( upd, data+offset, tail, NULL );
  printf(" long parts:     %s\n", str = ak_buffer_to_hexstr( result ));
  free( str ); result = ak_buffer_delete( result );

 /* Проверяем полученные результаты */
  ak_hash_clean( ctx );
  result = ak_hash_data( ctx, data, data_size, NULL );
  printf(" ak_hash_data(): %s\n", str = ak_buffer_to_hexstr( result ));
  free( str ); result = ak_buffer_delete( result );

 /* Освобождаем память и завершаем работу */
  generator = ak_random_delete( generator );
  upd = ak_update_delete( upd );
 return ak_libakrypt_destroy();
}
