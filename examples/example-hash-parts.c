 #include <stdio.h>
 #include <libakrypt.h>

/* длина хешируемых данных */
 #define data_size 65513

 int main( void )
{
  size_t i, bsize = 0, tail = 0, parts = 0;
  char *str = NULL;
  ak_hash ctx = NULL;
  ak_buffer result = NULL;
  ak_uint8 data[data_size], *ptr = NULL;
  ak_random generator = ak_random_new_lcg();

 /* 1. Инициализируем библиотеку */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
   return ak_libakrypt_destroy();

 /* 2. Вырабатываем данные для вычисления контрольной суммы.
       Мы устанавливаем генератор в фиксированное начальное состояние
       и заполняем массив значениями псевдослучаной последовательности */
  ak_random_randomize_uint64( generator, 10237 );
  ak_random_ptr( generator, data, data_size );

 /* 3. Создаем контекст функции хеширования */
  ctx = ak_hash_new_streebog256();

 /* 4. Хешируем данные как единый фрагмент при помощи одного
       вызова функции ak_hash_data() */
  result = ak_hash_data( ctx, data, data_size, NULL );
  printf("\n ak_hash_data():     %s\n", str = ak_buffer_to_hexstr( result ));
  free(str); result = ak_buffer_delete( result );

 /* 5. Хешируем данные фрагментами фиксированной длины.
       Теперь мы обрабатываем те же данные путем последовательного вызова
       функции ak_hash_update(), на вход которой подаются фрагменты длины
       64 байта.  Для получения значения хеш-кода используется вызов
       функции ak_hash_finalize().                                       */
  printf("\n parts with fixed length (%d)\n",
                          (int)(bsize = ak_hash_get_block_size( ctx )));
  printf(" count of parts:     %lu\n", parts = data_size/bsize );
  printf(" length of tail:     %lu\n", tail = data_size - parts*bsize );
  ak_hash_clean( ctx );
  for( i = 0, ptr = data; i < parts; i++, ptr += bsize )
     ak_hash_update( ctx, ptr, bsize );
  result = ak_hash_finalize( ctx, ptr, tail, NULL );
  printf(" hash value:         %s\n", str = ak_buffer_to_hexstr( result ));
  free(str); result = ak_buffer_delete( result );

 /* 6. Хешируем те же данные подавая на вход функции ak_hash_update()
       короткие фрагменты, длина которых определяется случайным образом */
  ak_hash_clean( ctx );
  ptr = data; tail = data_size;
  while( tail > 32 ) {
    /* вырабатываем случайное смещение, не превосходящее по длине 32 байт */
    parts = ak_random_uint8( generator )%32;
    ak_hash_update( ctx, ptr, parts );
    ptr += parts; tail -= parts;
  }
  result = ak_hash_finalize( ctx, ptr, tail, NULL );
  printf("\n small length parts: %s\n", str = ak_buffer_to_hexstr( result ));
  free(str); result = ak_buffer_delete( result );

 /* 7. Еще раз хешируем те же данные, но подавая на вход функции
       ak_hash_update() фрагменты длина которых случайна и превышает
       длину блока обрабатываемых данных                             */
  ak_hash_clean( ctx );
  ptr = data; tail = data_size;
  while( tail > 32 ) {
    if(( parts = ak_random_uint8( generator )%1024 ) > tail ) break;
    ak_hash_update( ctx, ptr, parts );
    ptr += parts; tail -= parts;
  }
  result = ak_hash_finalize( ctx, ptr, tail, NULL );
  printf(" long length parts:  %s\n", str = ak_buffer_to_hexstr( result ));
  free(str); result = ak_buffer_delete( result );

 /* 8. Хешируем данные c помощью всего лишь одного вызова функции ak_hash_finalize() */
  ak_hash_clean( ctx );
  result = ak_hash_finalize( ctx, data, data_size, NULL );
  printf(" ak_hash_finalize(): %s\n", str = ak_buffer_to_hexstr( result ));
  free(str); result = ak_buffer_delete( result );

 /* 9. Удаляем переменные и останавливаем библиотеку */
  ctx = ak_hash_delete( ctx );
  generator = ak_random_delete( generator );
 return ak_libakrypt_destroy();
}


