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
    
    struct bckey key;
    int error = ak_error_ok, audit = ak_log_get_level();

    ak_uint8 skey[32] = {
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88
    };

    /* синхропосылка */
    ak_uint8 iv2[4] = { 0x78, 0x56, 0x34, 0x12 };

    ak_uint8 out[112];

    /* ассоциированные (незашифровываемые) данные */
    ak_uint8 in2[56] = {
        0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99,
        0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22
    };

    ak_uint8 out2[56];

    /* под имитовставку */
    ak_uint8 tag[64]; 
    memset(tag, 0, sizeof(tag));

    /* контекст алгоритма аутентифицированного шифрования */ 
    struct aead ctx;    


    ak_oid oid = ak_oid_find_by_mode(aead);      
    ak_aead_create_oid(&ctx, ak_true, oid);

    /* ключ аутентификации */
    ak_uint8 authenticationKey[32] = { 
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,  
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 
    };           


    if(ak_error_ok != ak_aead_set_keys(&ctx, skey, sizeof(skey), authenticationKey, sizeof(authenticationKey)))
        return ak_error_get_value();

    /* выработка имитовставки (кода аутентификации) */
    if(ak_error_ok != ak_aead_mac(
            &ctx, /* контекст алгоритма аутентифицированного шифрования */
            in2, /* указатель на ассоциированные (незашифровываемые) данные */
            sizeof(in2), /* длина ассоциированных данных в байтах */
            iv2, /* указатель на синхропосылку (в режимах, где синхропосылка не используется
                        целесообразно использовать значение NULL) */
            ctx.iv_size, /* длина синхропосылки в октетах (в режимах, где синхропосылка не используется
                        целесообразно использовать значение 0) */ 
            tag, /* указатель на область памяти, куда помещается значение имитовставки */
            ctx.tag_size /* размер имитовставки в октетах */
            ))
        return ak_error_get_value();


    if(ak_error_ok != ak_bckey_create_magma(&key))
        return ak_error_get_value();


    if(ak_error_ok != ak_bckey_set_key(&key, skey, sizeof(skey)))
        return ak_error_get_value();

    // шифруем
    if(ak_error_ok != ak_bckey_ctr_acpkm(
            &key, /* Контекст ключа алгоритма блочного шифрования */
            in2, /* Указатель на область памяти, где хранятся входные
                (зашифровываемые/расшифровываемые) данные */
            out2, /* Указатель на область памяти, куда помещаются выходные
                (расшифровываемые/зашифровываемые) данные */
            sizeof(in2), /* Размер зашировываемых данных (в байтах) */
            16, /* Размер одной секции в байтах. Данная величина должна быть кратна длине блока
                                используемого алгоритма шифрования. */
            tag, /* имитовставка */
            sizeof(tag) /* длина имитовставки (в байтах) */
            ))
        return ak_error_get_value();

    // расшифровываем
    if (ak_error_ok != ak_bckey_ctr_acpkm(
            &key, /* Контекст ключа алгоритма блочного шифрования */
            out2, /* Указатель на область памяти, где хранятся входные
                (зашифровываемые/расшифровываемые) данные */
            out, /* Указатель на область памяти, куда помещаются выходные
                (расшифровываемые/зашифровываемые) данные */
            sizeof(in2), /* Размер зашировываемых данных (в байтах) */
            16, /* Размер одной секции в байтах. Данная величина должна быть кратна длине блока
                                используемого алгоритма шифрования. */
            tag, /* имитовставка */
            sizeof(tag) /* длина имитовставки (в байтах) */
            ))
        return ak_error_get_value();   

    // проверяем расшифрование
    if (memcmp(out, in2, sizeof(in2)) != 0) {
        ak_error_message(error = ak_error_not_equal_data, __func__, "incorrect data comparizon after acpkm decryption with magma cipher");
        return ak_error_not_equal_data;
    }
 
 ak_aead_destroy(&ctx);
 ak_bckey_destroy(&key);  
 ak_libakrypt_destroy();
 return EXIT_SUCCESS;
    
}
