/* пример иллюстрирует применение экспортируемых
   функций для работы с буфферами хранения данных */
 #include <libakrypt.h>

 int main( void )
{
  int i = 0;
  char str[128];
  ak_buffer ab[5]; /* массив из 5 указателей */
  ak_uint8 *ptr, data[12] = { 'w', 'e', 'l', 'c', 'o', 'm', 'e', 0, 'h', 'o', 'm', 'e' };
  const char *prime = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffacab87";

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( NULL )) return ak_libakrypt_destroy();

 /* создаем буффер фиксированного размера, память заполняется нулями */
  ab[0] = ak_buffer_new_size( 38 );
  ak_ptr_to_hexstr_static( /* выводим в строку шестнадцатеричное представление данных */
    ak_buffer_get_ptr(ab[0]), ak_buffer_get_size(ab[0]), str, sizeof(str), ak_false );
  printf("buffer[0]: %s (%d chars)\n", str, (int)strlen( str ));

 /* создаем буффер, помещая в него данные,
    записанные в строке в шестнадцатеричном виде */
  ab[1] = ak_buffer_new_hexstr( prime );
  printf("buffer[1]: "); /* производим побайтный доступ - от младших к старшим */
  for( i = 0; i < ak_buffer_get_size(ab[1]); i++ )
    printf("%02x ", ((ak_uint8 *)ak_buffer_get_ptr(ab[1]))[i] );
  printf("\n");

 /* создаем буффер фиксированного размера из тех же данных,
    поскольку данные содержат целое число, то мы записываем байты в обратном порядке */
  ab[2] = ak_buffer_new_hexstr_size( prime, 36, ak_true );
  printf("buffer[2]: "); /* производим побайтный доступ - от младших к старшим */
  for( i = 0; i < ak_buffer_get_size(ab[2]); i++ )
    printf("%02x ", ((ak_uint8 *)ak_buffer_get_ptr(ab[2]))[i] );
  printf("\n");

 /* создаем буффер из константных данных,
    при этом копирования не происходит - буффер просто содержит указатель на данные */
  ab[3] = ak_buffer_new_ptr( data, sizeof(data), ak_false );
  ak_ptr_to_hexstr_static( /* выводим в строку шестнадцатеричное представление данных */
    ak_buffer_get_ptr(ab[3]), ak_buffer_get_size(ab[3]), str, sizeof(str), ak_false );
  printf("buffer[3]: %s (%d chars)\n", str, (int)strlen( str ));

 /* создаем буффер, как хранилище строки символов, оканчивающейся нулем */
  ab[4] = ak_buffer_new_str( (char*) data );
  printf("buffer[4]: %s\n", ak_buffer_get_str(ab[4]));

 /* пример модификации данных в буффере: можно, но зачем?  */
  if(( ptr = (ak_uint8 *) ak_buffer_get_ptr( ab[4] )) != NULL ) {
    for( i = 0; i < ak_buffer_get_size( ab[4] ); i++ ) *ptr++ = '0';
  }
  ak_ptr_to_hexstr_static( /* выводим в строку шестнадцатеричное представление данных */
    ak_buffer_get_ptr(ab[4]), ak_buffer_get_size( ab[4] ), str, sizeof(str), ak_false );
  printf("buffer[4]: %s\n", str );

 /* очищаем память и закрываем библиотеку
    удаление ab[3], не владеющего данными, должно быть выполнено корректно */
  for( i = 0; i < 5; i++ ) ak_buffer_delete( ab[i] );
  ak_libakrypt_destroy();
 return 0;
}
