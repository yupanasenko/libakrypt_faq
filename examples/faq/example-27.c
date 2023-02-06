#include <stdio.h>
#include <libakrypt.h>
#include <libakrypt-base.h>

int main( void ) 
{
    if( ak_libakrypt_create( NULL ) != ak_true ) {
        /* инициализация выполнена не успешно, следовательно, выходим из программы */
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }
    
    /* Строка символов, содержащая последовательность шестнадцатеричных 
    цифр. Строка символов должна быть строкой, оканчивающейся нулем (NULL string)*/
    char str[] = "394B5\0";
    char a[64];
    /* Преобразование строки символов, содержащую последовательность 
    шестнадцатеричных цифр, в массив данных */
    ak_hexstr_to_ptr(str, a, sizeof(a), ak_true);

    for (int i = 0; i < sizeof(a); ++i) {
        printf("%c",a[i]);
    }
    printf("\n");
    
    ak_libakrypt_destroy();
    return EXIT_SUCCESS;
    
}
