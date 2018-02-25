/* ----------------------------------------------------------------------------------------------- *
   Пример, иллюстрирующий вычисление хеш-кода от данных,
   обрабатываемых фрагментами фиксированной длины

   Внимание: используются неэкспортируемые функции библиотеки
 * ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <ak_hash.h>
 #include <ak_random.h>

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
 int i = 0;
 struct hash ctx;
 struct random generator;
 ak_uint8 data[512], out[32], message[128];

 /* 1. инициализируем библиотеку с выводом сообщений в стандартный поток вывода ошибок */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) return ak_libakrypt_destroy();

 /* 2. вырабатываем массив случайных данных */
   ak_random_create_lcg( &generator );
   generator.random( &generator, data, sizeof( data ));
   ak_random_destroy( &generator );

 /* 3. вычисляем значение хеш-кода */
   printf("the first experiment:\n");
   ak_hash_create_streebog256( &ctx ); /* создаем контекст */
   for( i = 0; i < sizeof(data)/ctx.bsize; i++ ) {
     /* изменяем внутреннее состояние, при этом
        используем фрагмент данных, длина которых равна длине блока */
      ctx.update( &ctx, data+ctx.bsize*i, ctx.bsize );

     /* вычисляем значение хеш-кода для обработанного фрагмента данных;
        при финализации учитываем, что данные кратны длине блока,
        поэтому finalize не принимает данные для обработки */
      ctx.finalize( &ctx, NULL, 0, out );

     /* выводим результат */
      ak_ptr_to_hexstr_static( out, 32, message, 128, ak_false );
      printf("hash[%d]: %s\n", i, message );
   }
   ak_hash_destroy( &ctx );

 /* 4. вычисляем ту же последовательность хеш-кодов,
       но теперь для фрагментов с известной длины */
   printf("\nthe second experiment:\n");
   ak_hash_create_streebog256( &ctx );
   for( i = 0; i < sizeof(data)/ctx.bsize; i++ ) {
     /* вычисляем хеш-код от начала сообщения (фрагмент известной длины) */
      ak_hash_context_ptr( &ctx, data, ctx.bsize*(i+1), out );

     /* выводим результат */
      ak_ptr_to_hexstr_static( out, 32, message, 128, ak_false );
      printf("hash[%d]: %s\n", i, message );
   }
   ak_hash_destroy( &ctx );

 return ak_libakrypt_destroy(); /* останавливаем библиотеку и выходим */
}

/* ----------------------------------------------------------------------------------------------- */
