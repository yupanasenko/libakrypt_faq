#include <stdio.h>
#include <libakrypt.h>
#include <libakrypt-base.h>

int main() {
    struct bckey key;
    int error = ak_error_ok, audit = ak_log_get_level();
    /*значение ключа*/
    ak_uint8 skey[32] = {
      0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
      0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88
    };
    /*имитовставка*/
    ak_uint8 iv2[4] = { 0x78, 0x56, 0x34, 0x12 };
    /*указатель на область памяти, куда помещаются выходные данные*/
    ak_uint8 out[112];
    /*зашифровываемые данные*/
    ak_uint8 in2[56] = {
      0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
      0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
      0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
      0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
      0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99,
      0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22
    };

    /*Инициализация секретного ключа алгоритма блочного шифрования Магма*/
    if(ak_error_ok != ak_bckey_create_magma(&key))
        return ak_error_get_value();
    
    /* Инициализация контекста ключа значением, содержащимся в области памяти*/
    if(ak_error_ok != ak_bckey_set_key(&key, skey, sizeof(skey)))
        return ak_error_get_value();
   
    // шифруем
    if(ak_error_ok != ak_bckey_ctr_acpkm(
    &key, /*Контекст ключа алгоритма блочного шифрования,
    используемый для шифрования и порождения цепочки производных ключей.*/
    in2, /*Указатель на область памяти, где хранятся входные
    (зашифровываемые) данные*/
    out, /*Указатель на область памяти, куда помещаются выходные данные*/
    sizeof(in2), /*размер зашировываемых данных (в байтах)*/
    16, /*Размер одной секции в байтах. Данная величина должна быть кратна длине блока
    используемого алгоритма шифрования.*/
    iv2, /*имитовставка*/
    sizeof(iv2) /*длина имитовставки в байтах*/
    ))
      return ak_error_get_value();

    return 0;
}
