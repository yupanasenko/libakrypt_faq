/* ----------------------------------------------------------------------------------------------- *
   Пример, иллюстрирующий дублирование контекста функции хеширования.
   Внимание: используются неэкспортируемые функции библиотеки

 * ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <stdlib.h>
 #include <libakrypt.h>
 #include <ak_hash.h>
 #include <ak_random.h>

/* ----------------------------------------------------------------------------------------------- */
 int main( void )
{
  char *str = NULL;
  struct hash ctx1, ctx2;
  struct random generator;
  ak_uint8 buffer[132], out[32];

  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) return ak_libakrypt_destroy();

 /* вырабатываем случайный вектор */
  ak_random_create_lcg( &generator );
  generator.random( &generator, buffer, 132 );
  ak_random_destroy( &generator );

 /* вычисляем хеш от половинки вектора */
  ak_hash_create_gosthash94_csp( &ctx1 );
  ctx1.update( &ctx1, buffer, 64 );
  ctx1.finalize( &ctx1, NULL, 0, out );
  printf("half [1]:  %s\n", str = ak_ptr_to_hexstr( out, 32, ak_false )); free( str );

  ak_hash_create_gosthash94_csp( &ctx2 );
  ak_hash_context_ptr( &ctx2, buffer, 64, out );
  printf("half [2]:  %s\n\n", str = ak_ptr_to_hexstr( out, 32, ak_false )); free( str );

 /* вычисляем хеш от второй половинки и еще небольшой добавки */
  ctx1.update( &ctx1, buffer+64, 64 ); /* здесь мы используем данные,
                                          набранные в ходе предыдущего вызова функции update() */
  ctx1.finalize( &ctx1, buffer+128, 4, out );
                                       /* предыдущий вызов finalize() не испортил контекст,
                                          как впрочем и этот, можно прожолжать вызывать update() далее */
  printf("whole [1]: %s\n", str = ak_ptr_to_hexstr( out, 32, ak_false )); free( str );

 /* проверяем значение функции */
  ak_hash_context_ptr( &ctx2, buffer, 132, out );
  printf("whole [2]: %s\n", str = ak_ptr_to_hexstr( out, 32, ak_false )); free( str );

  ak_hash_destroy( &ctx1 );
  ak_hash_destroy( &ctx2 );
 return ak_libakrypt_destroy();
}
