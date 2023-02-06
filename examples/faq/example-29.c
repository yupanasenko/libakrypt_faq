#include <stdio.h>
#include <libakrypt-base.h>
#include <libakrypt.h>

/*Пример чтения строки текста из консоли*/

int main( void )
{
    if( ak_libakrypt_create( NULL ) != ak_true ) {
        /* инициализация выполнена не успешно, следовательно, выходим из программы */
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }
    char string[256];
    size_t len = 256;

    if(ak_string_read("Please, enter your message: \n",string,&len)!=ak_error_ok){
        printf("Error with reading your string!\n");
    }
    else{
        printf("Your string is: ");
        int i=0;
        for(i=0;i<len;i++){
            printf("%c",string[i]);
        }
    }
    
    ak_libakrypt_destroy();
    return EXIT_SUCCESS;
    
}
