#include <stdio.h>
#include <libakrypt-base.h>
#include <libakrypt.h>

/*Пример чтения пароля из консоли*/

int main( void )
{
    if( ak_libakrypt_create( NULL ) != ak_true ) {
        /* инициализация выполнена не успешно, следовательно, выходим из программы */
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }
    char string[256];
    size_t len = 256;

    if(ak_password_read(string,len)==ak_error_ok){
        printf("Error with reading your password!\n");
    }
    else{
        printf("Your password is: ");
        int i=0;
        for(i=0;i<len;i++){
            printf("%c",string[i]);
        }
    }
    
    ak_libakrypt_destroy();
    return EXIT_SUCCESS;
    
}
