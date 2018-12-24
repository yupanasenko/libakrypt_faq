/* Тестовый пример, иллюстрирующий работу
   с универсальным контекстом итеративного сжимающего отображения
   (функции вычисления имитовставки)

   Пример использует неэкспортируемые функции.

   test-internal-mgm03.c
*/


 #include <stdio.h>
 #include <stdlib.h>
 #include <ak_mac.h>

/* общие данные */
 static  ak_uint8 testkey[32] = { /* тестовое значение ключа */
     0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
     0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x87 };

 static  ak_uint8 testiv[16] = { /* инициализионный вектор (синхропосылка) */
     0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44, 0xa1, 0xb2, 0xc3, 0xd4, 0x15, 0x26, 0x37, 0x48 };
 static ak_uint8 testdata[4] = { 0x00, 0x11, 0xff, 0x12 }; /* данные */

 int main( void )
{
  size_t i = 0;
  struct mac ictx; /* универсальная структура */
  ak_buffer buffer = NULL;

  ak_libakrypt_create( ak_function_log_stderr );

 /* создаем контекст */
  if( ak_mac_context_create_oid( &ictx,
        ak_oid_context_find_by_name( "mgm-kuznechik" )) != ak_error_ok )
    return ak_libakrypt_destroy();

 /* устанавливаем ключевое значение */
  if( ak_mac_context_set_key( &ictx,
         testkey, sizeof( testkey ), ak_true ) != ak_error_ok ) {
    ak_mac_context_destroy( &ictx );
    return ak_libakrypt_destroy();
  }

 /* устанавливаем значение синхропосылки */
  if( ak_mac_context_set_iv( &ictx, testiv, sizeof( testiv )) != ak_error_ok ) {
    ak_mac_context_destroy( &ictx );
    return ak_libakrypt_destroy();
  }

  if(( buffer = ak_mac_context_ptr( &ictx, testdata, sizeof( testdata ), NULL )) != NULL ) {
    for( i = 0; i < buffer->size; i++ ) printf("%02X", ((ak_uint8 *)buffer->data)[i] );
    printf(" [icode]\n");
    ak_buffer_delete( buffer );
  }

  ak_mac_context_destroy( &ictx );
 return ak_libakrypt_destroy();
}
