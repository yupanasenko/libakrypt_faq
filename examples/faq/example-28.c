#include <stdio.h>
#include <libakrypt-base.h>
#include <libakrypt.h>

/*Пример чтения пароля из консоли*/

int main(){
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
}
