#include <stdio.h>
#include <string.h>
#include <libakrypt.h>

 int main( int argc, char *argv[] )
{
  ak_uint8 out[32];
  ak_handle handle = ak_error_wrong_handle;
  const char *fname;
  oid_modes_t mode;
  const char **names;
  oid_engines_t engine;

 /* инициализируем библиотеку. в случае возникновения ошибки завершаем работу */
  if( ak_libakrypt_create( NULL ) != ak_true ) {
    return ak_libakrypt_destroy();
  }

 /* создаем дескриптор алгоритма хеширования */
  handle = ak_handle_new_streebog256();

 /* получаем из созданного дескриптора информацию об алгоритме:
    имена, идентификатор, тип алгоритма и т.п. */
  ak_handle_get_oid( handle, &engine, &mode, &fname, &names );

  printf("%s (%s) [%s (%s), tag size: %u octets]\n", names[0], fname,
     ak_libakrypt_get_engine_name( engine ), ak_libakrypt_get_mode_name( mode ),
                                          (unsigned int) ak_handle_get_tag_size(handle));

 /* вычисляем контрольную сумму от заданного файла */
  if( argc == 1 ) fname = argv[0];
   else fname = argv[1];

  if( ak_handle_mac_file( handle, fname, out, sizeof( out )) != ak_error_ok ) printf("Wrong!");
    else {
      printf("%s (%s)\n", ak_ptr_to_hexstr( out, sizeof( out ), ak_false ), fname );
    }

 return ak_libakrypt_destroy();
}
