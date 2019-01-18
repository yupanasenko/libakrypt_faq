/* ----------------------------------------------------------------------------------------------- *
   Тестовый пример, иллюстрирующий возможность доступа к ключам алгоритма hmac

   Внимание: используются неэкспортируемые функции библиотеки
 * ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <stdlib.h>
 #include <ak_hmac.h>

 /* тестовое значение ключа */
 ak_uint32 key[8] = { 0x04030201, 0x08070605, 0x0c0b0a09, 0x000f0e0d, 0x78563412, 0xf0debc9a, 0x0, 0x01 };

 int main( void )
{
 struct hmac hx;
 char *str = NULL;
 ak_oid oid = NULL;
 ak_buffer buf = NULL;

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* перебираем все доступные алгоритмы хеширования и для каждого создаем контекст hmac */
  oid = ak_oid_context_find_by_engine( hmac_function );
  while( oid != NULL ) {
    if( oid->mode == algorithm ) {
      /* создаем контекст и присваиваем ему ключ */
      ak_hmac_context_create_oid( &hx, oid );
      ak_hmac_context_set_key( &hx, key, 32, ak_true );

      /* вычисляем имитовставку для константной области памяти */
      buf = ak_hmac_context_ptr( &hx, key, 32, NULL );
      str = ak_buffer_to_hexstr( buf, ak_false );
      printf("function: %s\nresult: %s\n\n", oid->name, str );
       if( str != NULL ) free( str );
      ak_buffer_delete( buf );

      /* уничтожаем контекст */
      ak_hmac_context_destroy( &hx );
    }
    oid = ak_oid_context_findnext_by_engine( oid, hmac_function );
  }

 /* останавливаем библиотеку и возвращаем результат сравнения */
 return ak_libakrypt_destroy();
}

