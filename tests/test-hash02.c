/*
  Пример, иллюстрирующий вычисление хеш-кода от данных,
  обрабатываемых фрагментами фиксированной длины
  В примере используются неэкспортируемые функции библиотеки.

  test-hash02.c
*/

 #include <stdio.h>
 #include <stdlib.h>
 #include <ak_hash.h>
 #include <ak_random.h>

 int main( void )
{
 struct hash ctx;
 struct random generator;
 size_t i = 0, bsize = 0;
 int result = EXIT_SUCCESS;
 ak_uint8 data[512], out[8][32], res[32];

 /* 1. инициализируем библиотеку с выводом сообщений в стандартный поток вывода ошибок */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
    return ak_libakrypt_destroy();

 /* 2. вырабатываем массив случайных данных */
   ak_random_context_create_lcg( &generator );
   ak_random_context_random( &generator, data, sizeof( data ));
   ak_random_context_destroy( &generator ); /* освобождаем генератор, поскольку он больше не нужен */

 /* 3. вычисляем значение хеш-кода:
       нарезаем исходные данные на фрагменты, длина которых
       совпадает с длиной блока обрабатываемых данных. Потом, последовательно, вычисляем
       значение хэш-кода для последовательно увеличивающихся фрагментов.

       Ипользуется тот факт, что функция finalize() не изменяет текущее состояние контекста. */

   printf("the first experiment:\n");
   ak_hash_context_create_streebog256( &ctx ); /* создаем контекст */
   bsize = ak_hash_context_get_block_size( &ctx );

   for( i = 0; i < sizeof(data)/bsize; i++ ) {
     /* изменяем внутреннее состояние, при этом
        для изменения внутреннего состояния используем фрагмент данных,
        длина которых равна длине блока

        вместо: ctx.mctx.update( &ctx.data.sctx, data+bsize*i, bsize ); */
       ak_hash_context_update( &ctx, data+bsize*i, bsize );

     /* вычисляем значение хеш-кода для обработанной последовательности фрагментов;
        при финализации учитываем, что данные кратны длине блока,
        поэтому finalize не принимает данные для обработки
        вместо: ctx.mctx.finalize( &ctx.data.sctx, NULL, 0, out[i], 32 ); */
       ak_hash_context_finalize( &ctx, NULL, 0, out[i], 32 );

     /* выводим результат */
      printf("hash[%u]: %s\n", (unsigned int)i,
                                         ak_ptr_to_hexstr( out[i], 32, ak_false ));
   }
   ak_hash_context_destroy( &ctx );

 /* 4. вычисляем ту же последовательность хеш-кодов,
       но теперь для фрагментов с известной заранее длиной */

   printf("\nthe second experiment:\n");
   ak_hash_context_create_streebog256( &ctx );
   for( i = 0; i < sizeof(data)/bsize; i++ ) {
     /* вычисляем хеш-код от начала сообщения (фрагмент известной длины) */
      ak_hash_context_ptr( &ctx, data, bsize*(i+1), res, 32 );

     /* выводим результат */
      printf("hash[%u]: %s", (unsigned int)i,
                                        ak_ptr_to_hexstr( res, 32, ak_false ));

     /* сравниваем новое значение с вычисленным ранее
        при различных результатах меняем возвращаемый результат */
      if( !ak_ptr_is_equal( out[i], res, 32 )) {
        printf(" Wrong\n"); result = EXIT_FAILURE;
      } else printf(" Ok\n");
   }
   ak_hash_context_destroy( &ctx );

 /* завершаем работу с библиотекой */
  ak_libakrypt_destroy();

 return result;
}
