/* ----------------------------------------------------------------------------------------------- *
   Тестовый пример, иллюстрирующий два подхода к вычислению имитовставки ГОСТ Р 34.13-2015.
   (через методы класса omac и через универсальный класс mac)

   Внимание: используются неэкспортируемые функции библиотеки
 * ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <ak_omac.h>
 #include <ak_mac.h>

 /* тестовое значение ключа */
 ak_uint32 key[8] = { 0x04030201, 0x08070605, 0x0c0b0a09, 0x000f0e0d, 0x78563412, 0xf0debc9a, 0x0, 0x01 };

 int main( void )
{
  struct mac mx;
  struct omac hx;
  ak_oid oid = NULL;
  unsigned int i = 0;
  int result = EXIT_SUCCESS;
  ak_uint8 data[36], out[16], out1[16], string[128];

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( ak_function_log_stderr )) return ak_libakrypt_destroy();

 /* вырабатываем случайные данные */
  memset( data, 127, sizeof( data ));

 /* перебираем все доступные алгоритмы хеширования и для каждого создаем контекст hmac */
  oid = ak_oid_context_find_by_engine( omac_function );
  while( oid != NULL ) {
    if( oid->mode == algorithm ) {
      printf("algorithm: %s\n", oid->name );

      for( i = 1; i <= sizeof( data ); i++ ) {
        /* создаем контекст и присваиваем ему ключ */
         ak_omac_context_create_oid( &hx, oid );
         ak_omac_context_set_key( &hx, key, 32, ak_true );
         ak_omac_context_ptr( &hx, data, i, out );
         ak_ptr_to_hexstr_static( out, hx.bkey.bsize, string, 128, ak_false );
         printf("[%4u] omac: %s -> ", i, string );

         ak_mac_context_create_omac( &mx, &hx );
         /* альтернативный вызов с созданием второго контекста omac
                              ak_mac_context_create_oid( &mx, oid ); */
         ak_mac_context_set_key( &mx, key, 32, ak_true );
         ak_mac_context_ptr( &mx, data, i, out1 );
         ak_ptr_to_hexstr_static( out1, mx.bsize, string, 128, ak_false );
         printf(" mac: %s ", string );
         if( memcmp( out, out1, mx.bsize ) == 0 ) printf(" Ok\n");
           else { result = EXIT_FAILURE; printf(" Wrong\n"); }

        /* уничтожаем контекст */
         ak_mac_context_destroy( &mx );
         ak_omac_context_destroy( &hx );
      }
    }
    oid = ak_oid_context_findnext_by_engine( oid, omac_function );
  }
  ak_libakrypt_destroy();

 return result;
}
