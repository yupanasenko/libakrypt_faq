#include <stdio.h>
#include <string.h>
#include <libakrypt.h>

 int main( int argc, char *argv[] )
{
  ak_uint8 out[32];
  char *fname = NULL;
  struct oid_info oid;
  ak_handle handle = ak_error_wrong_handle;


 /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( NULL ) != ak_true )
    return ak_libakrypt_destroy();

 /* создаем дескриптор алгоритма хеширования */
  if(( handle = ak_handle_new( "streebog256", NULL )) == ak_error_wrong_handle )
    return ak_libakrypt_destroy();

 /* получаем из созданного дескриптора информацию об алгоритме:
    имена, идентификатор, тип алгоритма и т.п. */
  ak_handle_get_oid( handle, &oid );

  printf("%s (%s) [%s (%s), tag size: %u octets]\n",
    oid.names[0], oid.id, ak_libakrypt_get_engine_name( oid.engine ),
      ak_libakrypt_get_mode_name( oid.mode ), (unsigned int) ak_handle_get_tag_size( handle ));

 /* выбираем имя файла */
  if( argc == 1 ) fname = argv[0];
   else fname = argv[1];
 /* вычисляем контрольную сумму */
  if( ak_handle_mac_file( handle, fname, out, sizeof( out )) != ak_error_ok ) printf("Wrong!");
    else {
      printf("%s (%s)\n", ak_ptr_to_hexstr( out, sizeof( out ), ak_false ), fname );
    }

 return ak_libakrypt_destroy();
}
