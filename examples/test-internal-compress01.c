/*
  Тестовый пример, иллюстрирующий возможность использования класса compress для
  вычисления значения бесключевой функции хеширования
  В примере используются неэкспортируемые функции библиотеки

  test-internal-compress02.c
*/

 #include <stdio.h>
 #include <ak_compress.h>

 int main( void )
{
  char *str = NULL;
  size_t offset = 0;
  int exitcode = EXIT_SUCCESS;
  ak_uint8 data[65536]; /* данные для хеширования */
  struct hash ctx; /* объект бесключевого хеширования */
  struct compress comp ; /* объект итеративного сжатия */
  ak_uint8 out[32], out2[32]; /* массивы для хранения результата вычислений */

 /* создаем данные для хеширования */
  memset( data, 0, 65536 ); data[1] = 0x11; data[65534] = 0x12;

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( NULL )) return ak_libakrypt_destroy();

 /* сперва хешируем данные (при известной длине) */
  ak_hash_context_create_gosthash94_csp( &ctx ); /* старый алгоритм хеширования с фиксированными таблицами */
  ak_hash_context_ptr( &ctx, data, 65536, out ); /* хешируем данные */
  printf("hash: %s\n", str = ak_ptr_to_hexstr( out, 32, ak_false )); free( str );


 /* теперь хешируем через итеративное сжатие */
  ctx.clean( &ctx ); /* очищаем объект от предыдущего мусора */
  ak_compress_context_create_hash( &comp, &ctx ); /* инициализируем
                контекст итерационного сжатия путем указания ссылки
                                 на объект бесключевого хеширования */

 /* теперь обрабатываем данные последовательными фрагментами случайной длины */
  while( offset < 65536 ) {
    size_t len = rand()%256; /* используем стандартный генератор ПСЧ */
    if( offset + len >= 65536 ) len = 65536 - offset;
    ak_compress_context_update( &comp, data+offset, len ); /* обновляем внутреннее состояние */
    offset += len;
  }
  ak_compress_context_finalize( &comp, NULL, 0, out2 ); /* получаем окончательное значение */
  printf("hash: %s\n", str = ak_ptr_to_hexstr( out2, 32, ak_false )); free( str );

 /* очищаем объекты */
  ak_compress_context_destroy( &comp );
  ak_hash_context_destroy( &ctx );

 /* проверяем, что результаты двух разных вычислений совпали */
  if( !ak_ptr_is_equal( out, out2, 32 )) exitcode = EXIT_FAILURE;

 /* останавливаем библиотеку и возвращаем результат сравнения */
  ak_libakrypt_destroy();
 return exitcode;
}
