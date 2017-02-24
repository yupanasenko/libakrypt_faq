 #include <stdio.h>
 #include <libakrypt.h>

/* длина хешируемых данных */
 #define data_size 65513

 int main( void )
{
  size_t i, bsize = 0, tail = 0, parts = 0;
  char *str = NULL;
  ak_hash ctx = NULL;
  ak_uint8 *ptr = NULL;
  ak_uint8 data[data_size], /* хешируемые данные */
           out[32]; /* массив для хранения результата вычислений */

 /* 1. Инициализируем библиотеку */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
   return ak_libakrypt_destroy();

 /* 2. Инициализируем хешируемые данные фиксированными значениями */
   memset( data, 0, data_size );
   data[0] = 0xa; data[data_size-1] = 0xf;

 /* 3. Создаем контекст функции хеширования */
  ctx = ak_hash_new_streebog256();

 /* 4. Хешируем данные как единый фрагмент при помощи одного
       вызова функции ak_hash_data() */
  ak_hash_data( ctx, data, data_size, out );
  printf(" ak_hash_data(): %s\n", str = ak_ptr_to_hexstr( out, 32, ak_false ));
  free(str);

 /* 5. Теперь мы обрабатываем те же данные путем последовательного вызова
       функции ak_hash_update(), на вход которой подаются фрагменты длины
       64 байта.  Для получения окончательного значения хеш-кода
       используется вызов функции ak_hash_finalize().                     */
  bsize = ak_hash_get_block_size( ctx );
  printf(" count of parts: %lu\n", parts = data_size/bsize );
  printf(" length of tail: %lu\n", tail = data_size - parts*bsize );
  printf(" total length:   %lu = parts*%lu + tail\n", parts*bsize + tail, bsize );

  for( i = 0, ptr = data; i < parts; i++, ptr += bsize ) ak_hash_update( ctx, ptr, bsize );
  ak_hash_finalize( ctx, ptr, tail, out );
  printf(" update value:   %s\n", str = ak_ptr_to_hexstr( out, 32, ak_false ));
  free(str);

 /* 9. Удаляем переменные и останавливаем библиотеку */
  ctx = ak_hash_delete( ctx );
 return ak_libakrypt_destroy();
}


