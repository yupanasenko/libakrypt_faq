/* ----------------------------------------------------------------------------------------------- *
   Тестовый пример, иллюстрирующий возможность прямого доступа к полям секретного ключа

   Внимание: используются неэкспортируемые функции библиотеки
 * ----------------------------------------------------------------------------------------------- */
 #include <stdio.h>
 #include <ak_skey.h>

 /* предварительное описание */
 void ak_skey_context_print( ak_skey skey, FILE *fp );

 /* тестовое значение ключа */
 ak_uint32 key[8] = { 0x04030201, 0x08070605, 0x0c0b0a09, 0x000f0e0d, 0x78563412, 0xf0debc9a, 0x0, 0x01 };

 int main( void )
{
  int i = 0;
  struct skey skey;

 /* инициализируем библиотеку */
  if( !ak_libakrypt_create( NULL )) return ak_libakrypt_destroy();

 /* создаем ключ */
  ak_skey_context_create( &skey, 32, 8 );
  printf("\n"); ak_skey_context_print( &skey, stdout );

 /* присваиваем ключу константное значение */
  ak_skey_context_set_key( &skey, key, 32, ak_true );
  printf("\n"); ak_skey_context_print( &skey, stdout );
 /* несколько раз перемаскируем ключ */
  for( i = 0; i < 3; i++ ) {
    skey.set_mask( &skey );
    printf("\n"); ak_skey_context_print( &skey, stdout );
  }

 /* снимаем маску */
  skey.unmask( &skey );
  printf("\n"); ak_skey_context_print( &skey, stdout );

 /* в заключение, несколько раз присваиваем случайное значение */
  printf("\ntwo random keys\n");
  for( i = 0; i < 2; i++ ) {
    ak_skey_context_set_key_random( &skey, &skey.generator );
    printf("\n"); ak_skey_context_print( &skey, stdout );
  }

 ak_skey_context_destroy( &skey );
 /* останавливаем библиотеку и возвращаем результат сравнения */
 return ak_libakrypt_destroy();
}

 void ak_skey_context_print( ak_skey skey, FILE *fp )
{
  ak_uint8 string[512];

  ak_ptr_to_hexstr_static( skey->key.data, skey->key.size, string, 512, ak_false );
  fprintf( fp, "key:   %s (%u octets)\n", string, (ak_uint32)skey->key.size );

  ak_ptr_to_hexstr_static( skey->mask.data, skey->mask.size, string, 512, ak_false );
  fprintf( fp, "mask:  %s (%u octets)\n", string, (ak_uint32)skey->mask.size );

  ak_ptr_to_hexstr_static( skey->icode.data, skey->icode.size, string, 512, ak_false );
  fprintf( fp, "icode: %s (%u octets, ", string, (ak_uint32)skey->icode.size );
  if( skey->check_icode != NULL ) {
    if( skey->check_icode( skey ) == ak_true ) fprintf( fp, "Ok)\n");
      else fprintf( fp, "Wrong)\n");
  }

  ak_ptr_to_hexstr_static( skey->number.data, skey->number.size, string, 512, ak_false );
  fprintf( fp, "key number: %s (%u octets)\n", string, (ak_uint32)skey->number.size );

  fprintf( fp, "flags: %X (", skey->flags );
  if(( skey->flags&skey_flag_set_key ) == 0 ) fprintf( fp, "no key, ");
    else fprintf( fp, "key assigned, ");
  if(( skey->flags&skey_flag_set_mask ) == 0 ) fprintf( fp, "no mask, ");
    else fprintf( fp, "mask assigned, ");
  if(( skey->flags&skey_flag_set_icode ) == 0 ) fprintf( fp, "no icode, ");
    else fprintf( fp, "icode assigned, ");
  if(( skey->flags&skey_flag_data_free ) == 0 ) fprintf( fp, "no internal data");
    else fprintf( fp, "internal data assigned, ");
  fprintf( fp, ")\n");
}

