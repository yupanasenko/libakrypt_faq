/*
  Пример, иллюстрирующий вычисление хеш-кода от данных,
  обрабатываемых фрагментами фиксированной длины
  В примере используются неэкспортируемые функции библиотеки.

  test-internal-hash02.c
*/

 #include <stdio.h>
 #include <stdlib.h>
 #include <ak_hash.h>
 #include <ak_random.h>

 int main( void )
{
 size_t i = 0;
 struct hash ctx;
 struct random generator;
 int result = EXIT_SUCCESS;
 ak_uint8 data[512], out[8][32], res[32], message[128];

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
   for( i = 0; i < sizeof(data)/ctx.bsize; i++ ) {
     /* изменяем внутреннее состояние, при этом
        для изменения внутреннего состояния используем фрагмент данных,
        длина которых равна длине блока */
      ctx.update( &ctx, data+ctx.bsize*i, ctx.bsize );

     /* вычисляем значение хеш-кода для обработанной последовательности фрагментов;
        при финализации учитываем, что данные кратны длине блока,
        поэтому finalize не принимает данные для обработки */
      ctx.finalize( &ctx, NULL, 0, out[i] );

     /* выводим результат */
      ak_ptr_to_hexstr_static( out[i], 32, message, 128, ak_false );
      printf("hash[%u]: %s\n", (unsigned int)i, message );
   }
   ak_hash_context_destroy( &ctx );

 /* 4. вычисляем ту же последовательность хеш-кодов,
       но теперь для фрагментов с известной заранее длиной */

   printf("\nthe second experiment:\n");
   ak_hash_context_create_streebog256( &ctx );
   for( i = 0; i < sizeof(data)/ctx.bsize; i++ ) {
     /* вычисляем хеш-код от начала сообщения (фрагмент известной длины) */
      ak_hash_context_ptr( &ctx, data, ctx.bsize*(i+1), res );

     /* выводим результат */
      ak_ptr_to_hexstr_static( res, 32, message, 128, ak_false );
      printf("hash[%u]: %s\n", (unsigned int)i, message );

     /* сравниваем новое значение с вычисленным ранее
        при различных результатах меняем возвращаемый результат */
      if( !ak_ptr_is_equal( out[i], res, 32 )) result = EXIT_FAILURE;
   }
   ak_hash_context_destroy( &ctx );
 /* завершаем работу с библиотекой */
  ak_libakrypt_destroy();

 return result;
}
