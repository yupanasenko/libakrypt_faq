 #include <libakrypt.h>

 int main( void )
{
 int i = 0, j = 0;
 ak_uint8 buffer[128];
 ak_random generator = NULL; /* указатели на генераторы псевдо-случайных чисел */
 char *filename = "../libakrypt-0.x/examples/example-random-sys.c";

 /* инициализируем библиотеку */
 if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) return ak_libakrypt_destroy();

 /* создаем генератор, циклически считывающий значения из заданного файла */
 if(( generator = ak_random_new_file( filename )) != NULL ) {
    printf(" -- random values from fixed file %s:\n", filename );
    for( i = 0; i < 16; i++ ) {
       ak_random_ptr( generator, buffer, 128 );
       for( j = 0; j < 128; j++ ) printf( "%c", buffer[j] );
    }
    printf("\n");
    generator = ak_random_delete( generator );
 }

#ifdef __linux
 /* создаем генератор, считывающий данные из /dev/random */
 if(( generator = ak_random_new_file( "/dev/random" )) != NULL ) {
    printf(" -- random values from /dev/random:\n");
    for( i = 0; i < 128; i++ ) printf(" %02X", ak_random_uint8( generator ));
    printf("\n");
    generator = ak_random_delete( generator );
 }
#endif
#ifdef _WIN32
  printf(" -- random values from Windows CryptGetRandom() function:\n");
  generator = ak_random_new_winrtl();
  for( i = 0; i < 128; i++ ) printf(" %02X", ak_random_uint8( generator ));
  printf("\n");
  generator = ak_random_delete( generator );
#endif

 return ak_libakrypt_destroy();
}

