/*
   Тестовый пример, иллюстрирующий возможность использования класса compress для
   вычисления значений бесключевой функции хеширования
   В примере используются неэкспортируемые функции библиотеки

   test-internal-compress02.c
*/

 #include <stdio.h>
 #include <ak_compress.h>

 int main( void )
{
 struct hash hctx;
 struct compress ctx;
 struct random generator;
 int seed = 0, exitcode = EXIT_SUCCESS;
 ak_uint8 data[800], out[32], out2[32], string[512];

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( NULL )) return ak_libakrypt_destroy();

 /* создаем генератор, инициализируем его и вырабатываем данные */
  ak_random_context_create_lcg( &generator );
  ak_random_context_randomize( &generator, &seed, 4 );
  ak_random_context_random( &generator, data, 800 );

 /* создаем контекст хеширования и контекст сжатия */
  ak_hash_context_create_streebog256( &hctx );
  ak_compress_context_create_hash( &ctx, &hctx );

 /* проводим вычисления */
  ak_compress_context_update( &ctx, data, 100 );
  ak_compress_context_update( &ctx, data+100, 100 );
  ak_compress_context_update( &ctx, data+200, 100 );

  ak_compress_context_finalize( &ctx, NULL, 0, out ); /* закрываем первые 3 сотни байт */
                                /* здесь мы завершаем вычисления без добавления данных */
  ak_ptr_to_hexstr_static( out, 32, string, 512, ak_false );
  printf("300: %s\n", string );

  ak_compress_context_finalize( &ctx, data+300, 100, out ); /* закрываем 4ю сотню байт */
                      /* здесь мы завершаем вычисления c добавлением данных (100 байт) */
  ak_ptr_to_hexstr_static( out, 32, string, 512, ak_false );
  printf("400: %s\n", string );

  ak_compress_context_update( &ctx, data+400, 100 );
  ak_compress_context_update( &ctx, data+500, 100 );
  ak_compress_context_update( &ctx, data+600, 100 );
  ak_compress_context_finalize( &ctx, data+700, 10, out ); /* закрываем 710 байт */
  ak_ptr_to_hexstr_static( out, 32, string, 512, ak_false );
  printf("710: %s\n", string );

  ak_compress_context_finalize( &ctx, data+710, 0, out ); /* закрываем 710 байт еще раз */
                     /*  вычисления завершаются с данными НУЛЕВОЙ длины */
  ak_ptr_to_hexstr_static( out, 32, string, 512, ak_false );
  printf("710: %s\n", string );

  ak_compress_context_finalize( &ctx, data+710, 20, out ); /* закрываем 730 байт */
  ak_ptr_to_hexstr_static( out, 32, string, 512, ak_false );
  printf("730: %s\n", string );

  ak_compress_context_update( &ctx, data+730, 70 );
  ak_compress_context_finalize( &ctx, NULL, 0, out ); /* закрываем все */
  ak_ptr_to_hexstr_static( out, 32, string, 512, ak_false );
  printf("800: %s\n", string );

 /* проверяем результаты */
  printf("\n");
  hctx.clean( &hctx ); /* очищаем контекст, иначе кердык */
  ak_hash_context_ptr( &hctx, data, 300, out2 );
  ak_ptr_to_hexstr_static( out2, 32, string, 512, ak_false );
  printf("300: %s\n", string );

  hctx.clean( &hctx ); /* очищаем контекст, иначе кердык */
  ak_hash_context_ptr( &hctx, data, 400, out2 );
  ak_ptr_to_hexstr_static( out2, 32, string, 512, ak_false );
  printf("400: %s\n", string );

  hctx.clean( &hctx ); /* очищаем контекст, иначе кердык */
  ak_hash_context_ptr( &hctx, data, 710, out2 );
  ak_ptr_to_hexstr_static( out2, 32, string, 512, ak_false );
  printf("710: %s\n", string );

  hctx.clean( &hctx ); /* очищаем контекст, иначе кердык */
  ak_hash_context_ptr( &hctx, data, 730, out2 );
  ak_ptr_to_hexstr_static( out2, 32, string, 512, ak_false );
  printf("730: %s\n", string );

  hctx.clean( &hctx ); /* очищаем контекст, иначе кердык */
  ak_hash_context_ptr( &hctx, data, 800, out2 );
  ak_ptr_to_hexstr_static( out2, 32, string, 512, ak_false );
  printf("800: %s\n", string );

 /* сравниваем результаты */
  if( !ak_ptr_is_equal( out, out2, 32 )) exitcode = EXIT_FAILURE;

 /* подчищаем память */
  ak_random_context_destroy( &generator );
  ak_hash_context_destroy( &hctx );
  ak_compress_context_destroy( &ctx );

 /* останавливаем библиотеку и возвращаем результат сравнения */
  ak_libakrypt_destroy();

 return exitcode;
}
