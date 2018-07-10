/* Тестовый пример, иллюстрирующий процедуры поиска oid по заданному криптографическому
   механизму, а также использование oid для создания и удаления объектов.
   Пример использует неэкспортируемые функции.

   test-internal-oid01.c
*/

 #include <stdio.h>
 #include <ak_oid.h>
 #include <ak_random.h>

 int main( void )
{
 ak_oid oid;
 int count = 0;
 ak_uint8 data[32], string[128];

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr ))
    return ak_libakrypt_destroy();

 /* перебираем все oid для генераторов псевдослучайных чисел */
  oid = ak_oid_context_find_by_engine( random_generator );

  while( oid != NULL ) {
    struct random generator;

   /* используя oid, создаем объект и вырабатываем случайные данные */
    (( ak_function_random *)( oid->func.create ))( &generator );
    ak_random_context_random( &generator, data, 32 );
    ak_ptr_to_hexstr_static( data, 32, string, 128, ak_false );
   /* выводим сгенерированные данные и информацию о генераторе,
                                используя oid созданного генератора */
    printf("%02d: %s [%s, %s]", ++count, string,
                             generator.oid->name, generator.oid->id );
   /* проверка совпадения oid */
    if( generator.oid != oid ) printf(" wrong oid pointer\n");
     else printf("\n");

   /* удаляем генератор */
    (( ak_function_random *)( oid->func.destroy ))( &generator );

   /* выполняем поиск следующего */
    oid = ak_oid_context_findnext_by_engine( oid, random_generator );
  }

 printf("founded %d random generators\n", count );
 ak_libakrypt_destroy();
 return EXIT_SUCCESS;
}
