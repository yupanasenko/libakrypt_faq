 #include <libakrypt.h>

 int main( void )
{
 int i = 0, j = 0;
 ak_uint8 buffer[128];
 ak_random generator = NULL, /* указатели на генераторы псевдо-случайных чисел */
          fgenerator = NULL;

 /* инициализируем библиотеку */
 if( ak_libakrypt_create( ak_function_log_stderr ) != ak_true ) return ak_libakrypt_destroy();

 /* создаем генератор, циклически считывающий значения из заданного файла */
 if(( fgenerator =
           ak_random_new_file( "../libakrypt-0.x/examples/example-dev-random.c" )) != NULL ) {
    printf(" -- random values from fixed file:\n");
    for( i = 0; i < 20; i++ ) {
       ak_random_ptr( fgenerator, buffer, 128 );
       for( j = 0; j < 128; j++ ) printf( "%c", buffer[j] );
    }
    printf("\n");
    fgenerator = ak_random_delete( fgenerator );
 }
 /* создаем генератор, считывающий данные из /dev/random */
 if(( generator = ak_random_new_file( "/dev/random" )) != NULL ) {
    printf(" -- random values from /dev/random:\n");
    for( i = 0; i < 128; i++ ) printf(" %02X", ak_random_uint8( generator ));
    printf("\n");
    generator = ak_random_delete( generator );
 }
 return ak_libakrypt_destroy();
}

