 #include <libakrypt.h>

 int main( void )
{
 ak_handle handle; /* дескриптор генератора */
 ak_buffer buffer = NULL; /* буффер для хранения случайных значений */

 /* инициализируем библиотеку */
  if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true )
    return ak_libakrypt_destroy();

 /* создаем генератор */
  if(( handle = ak_random_new_lcg()) == ak_error_wrong_handle )
    return ak_libakrypt_destroy();

 /* вырабатываем случайные данные и выводим их в консоль */
  if(( buffer = ak_random_buffer( handle, 128 )) != NULL ) {
    char *str = NULL;
    printf("random data (%d bytes):\n%s\n",
             (int) ak_buffer_get_size( buffer),
             str = ak_buffer_to_hexstr( buffer, ak_false ));
    free( str );

   /* удаляем буффер */
    buffer = ak_buffer_delete( buffer );
  }

 /* заметим, что удаление генератора происходит при вызове
    функции остановки библиотеки */
 return ak_libakrypt_destroy();
}
