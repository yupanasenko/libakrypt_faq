 #include <stdio.h>
 #include <libakrypt.h>

/* длина хешируемых данных */
 #define data_size 65513

 int main( void )
{
 char *str = NULL;
 ak_int64 i, bsize = 0, parts = 0, tail = 0;
 ak_hash ctx = NULL; /* определяем контекст */
 ak_uint8 *data = NULL, *ptr = NULL; /* определяем указатель на хешируемые данные */
 ak_uint8 result[64]; /* массив для хранения результатов вычислений */

 /* 1. Инициализируем библиотеку */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) goto exit;

 /* 2. Моделируем данные для хеширования */
  if(( ptr = data = malloc( data_size )) == NULL ) goto exit;
  for( i = 0; i < data_size; i++ ) data[i] = i&0xFF;

 /* 3. Создаем контекст функции хеширования */
  if(( ctx = ak_hash_new_streebog256()) == NULL ) goto exit;
  ak_hash_clean( ctx ); /* инициализируем и очищаем контекст */

 /* 4. Вычисляем количество и длины обрабатываемых фрагментов */
  bsize = ak_hash_get_block_size( ctx );
  printf(" count of parts: %lu\n", parts = data_size/bsize );
  printf(" length of tail: %lu\n", tail = data_size - parts*bsize );

 /* 5. Фрагментируем и обрабатываем данные */
  for( i = 0; i < parts; i++ ) {
     ak_hash_update( ctx, data, bsize );
     data += bsize;
  }
 /* 6. Выполняем завершающее преобразование */
  ak_hash_final( ctx, data, tail );

 /* 7. Получаем результат хеширования */
  memset( result, 0, 64 );
  ak_hash_get_code( ctx, result );
  printf("as is:        %s\n", str = ak_ptr_to_hexstr( result, ak_hash_get_code_size( ctx ), ak_false ));
  free(str);

 /* 8. Проверяем результат */
  memset( result, 0, 64 );
  ak_hash_data( ctx, ptr, data_size, result );
  printf("ak_hash_data: %s\n", str = ak_ptr_to_hexstr( result, ak_hash_get_code_size( ctx ), ak_false ));
  free(str);

 /* 9. Останавливаем библиотеку и выходим */
  ctx = ak_hash_delete( ctx );
  exit: if( ptr != NULL ) free( ptr );
 return ak_libakrypt_destroy();
}


