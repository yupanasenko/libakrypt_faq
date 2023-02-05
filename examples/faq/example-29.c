#include <stdio.h>
#include <libakrypt-base.h>
#include <libakrypt.h>

/*Пример чтения строки текста из консоли*/

int main(){
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
}
