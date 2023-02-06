#include <libakrypt.h>
#include <libakrypt-base.h>

/*Пример чтения электронной подписи из файла */

int main( void ) 
{
    if( ak_libakrypt_create( NULL ) != ak_true ) {
       /* инициализация выполнена не успешно, следовательно, выходим из программы */
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }
    
    struct file aaa;
    
    ak_uint8 sign[128];
    
    char fileout[128] = "ls.txt";
    
    ak_file_open_to_read(&aaa, fileout);
    ak_file_read(&aaa, sign, 128);
    
    ak_libakrypt_destroy();
    return EXIT_SUCCESS;
}
