#include <kc_tools.h>
#include "kc_libakrypt.h"
#include <kc_transform.h>
#include "kc_key_manager.h"
#include <assert.h>

int read_keys_from_container(byte* password, size_t pwd_size, byte* inp_container, size_t inp_container_size, struct extended_key*** ppp_out_keys, ak_uint8* num_of_out_keys) {

    int error;
    uint8_t i;
    s_pkcs_15_token main_token;
    struct bckey kek;
    struct extended_key** pp_keys;

    error = ak_error_ok;
    memset(&main_token, 0, sizeof(main_token));

    /* Разбираем контейнер */
    if((error = pkcs_15_parse_token(inp_container, inp_container_size, &main_token)) != ak_error_ok){
        return ak_error_message(error, __func__, "problem with parsing container");
    }

    if(!main_token.m_info_size){
        return ak_error_message(ak_error_invalid_value, __func__, "key management info absent");
    }

    if(!main_token.m_obj_size){
        return ak_error_message(ak_error_invalid_value, __func__, "objects absent");
    }

    /* Создаем ключ KEK */
    //TODO FIX
    ak_bckey_context_create_magma(&kek);
    gen_sec_kek_from_pwd(&kek, password, pwd_size, main_token.mpp_key_infos[0]);

    /* Расшифровываем данные и создаем объекты extended_key */
    pp_keys = malloc(main_token.m_obj_size * sizeof(struct extended_key*));
    if(!pp_keys)
        return ak_error_message(ak_error_null_pointer, __func__, "alloc memory fail");

    *num_of_out_keys = 0;
    for(i = 0; i < main_token.m_obj_size; i++)
    {
        pp_keys[i] = calloc(1, sizeof(struct extended_key));
        if(!pp_keys[i])
            return ak_error_message(ak_error_null_pointer, __func__, "alloc memory fail");

        if(get_extended_key(main_token.mpp_pkcs_15_objects[i], &kek.key, pp_keys[i]) != ak_error_ok)
            pp_keys[i] = NULL;
        else
            *num_of_out_keys += 1;
    }

    /* Освобождаем память */
    free_pkcs_15_token(&main_token);

    *ppp_out_keys = pp_keys;

    return ak_error_ok;
}

static int get_extended_key(s_pkcs_15_object* p_obj, struct skey* p_kek, struct extended_key* p_key)
{
    int error;
    s_gost_sec_key* p_pkcs_sec_key;
    ak_bckey p_libakrypt_sec_key;

    assert(p_obj && p_kek && p_key);

    if(p_obj->m_type != SEC_KEY)
        return ak_error_message(ak_error_invalid_value, __func__, "only secret key support");

    p_key->key_type = SEC_KEY;

    p_pkcs_sec_key = p_obj->m_obj.mp_sec_key;

    /* Создаем контекст секретного ключа */
    p_libakrypt_sec_key = calloc(1, sizeof(struct bckey));
    if(strcmp(p_pkcs_sec_key->m_key_type_gost, "1.2.643.7.1.1.5.1") == 0)
        ak_bckey_context_create_magma(p_libakrypt_sec_key);
    else if(strcmp(p_pkcs_sec_key->m_key_type_gost, "1.2.643.7.1.1.5.2") == 0)
        ak_bckey_context_create_kuznechik(p_libakrypt_sec_key);
    else
        return ak_error_message(ak_error_invalid_value, __func__, "only R 34.11 - 2015 key support");

    /* Заполняем общие атрибуты (объектов, ключей, секретных ключей) */
    // метка ключа
    if(p_pkcs_sec_key->m_obj_attrs.m_label)
    {
        p_key->label = malloc(strlen((char*)p_pkcs_sec_key->m_obj_attrs.m_label) + 1);
        strcpy((char*)p_key->label, (char*)p_pkcs_sec_key->m_obj_attrs.m_label);
        //asn_utf8_to_byte_arr(&p_pkcs_sec_key->m_obj_attrs.m_label, &p_key->key_label);
    }

    // уникальный идентификатор ключа
    set_key_id(p_pkcs_sec_key->m_key_attrs.m_id, &p_libakrypt_sec_key->key);

    // флаги предназначения ключа
    set_usage_flags(p_pkcs_sec_key->m_key_attrs.m_usage, &p_key->flags);

    // дата начала периода действия ключа
    if(p_pkcs_sec_key->m_key_attrs.m_start_date)
        asn_generalized_time_to_date(p_pkcs_sec_key->m_key_attrs.m_start_date, p_key->start_date);

    // дата окончания периода действия ключа
    if(p_pkcs_sec_key->m_key_attrs.m_end_date)
        asn_generalized_time_to_date(p_pkcs_sec_key->m_key_attrs.m_end_date, p_key->end_date);

    /* Расшифровываем ключ */
    if((error = decrypt_enveloped_data(&p_pkcs_sec_key->m_enveloped_data, p_kek, &p_libakrypt_sec_key->key)) != ak_error_ok)
    {
        ak_bckey_context_destroy(p_libakrypt_sec_key);
        return ak_error_message(error, __func__, "problem with decrypting enveloped data");
    }

    p_key->key.sec_key = p_libakrypt_sec_key;

    return ak_error_ok;
}

static int decrypt_enveloped_data(s_enveloped_data* p_enveloped_data, ak_skey p_kek, ak_skey p_libakrypt_key)
{
    int error;
    struct bckey cek;
    struct buffer encrypted_content;
    struct buffer encrypted_content_mac;
    struct buffer iv;
    s_gost28147_89_prms* p_content_enc_prms;

    assert(p_enveloped_data && p_kek && p_libakrypt_key);

    /* Проверяем наличие информации Recipient info */
    if(!p_enveloped_data->m_ri_size)
        return ak_error_message(ak_error_invalid_value, __func__, "recipient info absent");


    /* Определяем алгоритм шифрования контента */
    if(!p_enveloped_data->m_content_enc_alg_id)
        return ak_error_message(ak_error_invalid_value, __func__, "encrypted_content encryption algorithm identifier absent");

    if(strcmp(p_enveloped_data->m_content_enc_alg_id, "1.2.643.2.4.3.2.2") == 0)
        ak_bckey_context_create_magma(&cek);
    else if(strcmp(p_enveloped_data->m_content_enc_alg_id, "1.2.643.2.4.3.2.3") == 0)
        ak_bckey_context_create_kuznechik(&cek);
    else
        return ak_error_message_fmt(ak_error_invalid_value, __func__, "this algorithm ('%s') doesn't support", p_enveloped_data->m_content_enc_alg_id);

    /* Устанавливаем параметры шифрования */
    if(p_enveloped_data->m_prm_set_type != GOST_CONTENT_ENC_SET)
        return ak_error_message(ak_error_invalid_value, __func__, "only CryptoPro parameters support");

    //TODO: Разобраться с идентификатором набора параметров
    p_content_enc_prms = p_enveloped_data->m_prm_set.p_content_enc_prm_set;

    if(!p_content_enc_prms->m_iv.mp_value)
        return ak_error_message(ak_error_invalid_value, __func__, "initialization vector absent");

    ak_buffer_create(&iv);
    ak_buffer_set_ptr(&iv, p_content_enc_prms->m_iv.mp_value, p_content_enc_prms->m_iv.m_val_len, ak_true);

    /* Расшифровываем ключ шифрования контента (CEK) */
    if((error = decrypt_content_enc_key(p_enveloped_data->mpp_recipient_infos[0], p_kek, &cek.key)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with decrypting CEK");

    /* Расшифровываем контент */
    ak_buffer_create_size(&encrypted_content, p_enveloped_data->m_encrypted_content.m_val_len - 4);
    memcpy(encrypted_content.data, p_enveloped_data->m_encrypted_content.mp_value, encrypted_content.size);
    ak_buffer_create_size(&encrypted_content_mac, 4);
    memcpy(encrypted_content_mac.data, p_enveloped_data->m_encrypted_content.mp_value + encrypted_content.size, encrypted_content_mac.size);

    /*TODO: комментарий для Алексея Юрьевича: здесь необходимо вызвать
            фунцию расшифрования данных и сравнить имитовставку */

    /* Переносим значение ключа, маски, счетчика в структуру skey */
    if((error = pkcs_15_parse_gost_key_value_mask(&encrypted_content, &p_libakrypt_key->key, &p_libakrypt_key->mask, &p_libakrypt_key->resource.counter)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with parsing key value mask");

    /* Устанавливаем флаги наличия ключа и маски */
    p_libakrypt_key->flags |= skey_flag_set_key | skey_flag_set_mask;

    /* Перемаскируем ключ */
    if((error = p_libakrypt_key->set_mask(p_libakrypt_key)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with key remasking");

    /* Вычисляем контрольную сумму ключа */
    if((error = p_libakrypt_key->set_icode(p_libakrypt_key)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with setting icode");

    /* Устанавливаем флаг наличия контрольной суммы */
    p_libakrypt_key->flags |= skey_flag_set_icode;

    return ak_error_ok;
}

static int decrypt_content_enc_key(s_recipient_info* p_recipient_info, ak_skey p_kek, ak_skey p_cek)
{
    int error;
    struct buffer encrypted_cek;
    struct buffer encrypted_cek_mac;
    s_gost28147_89_key_wrap_prms* p_key_enc_prms;

    if(p_recipient_info->m_type != KEKRI)
        return ak_error_message(ak_error_invalid_value, __func__, "only kekri support");

    s_kekri* p_kekri = p_recipient_info->m_ri.mp_kekri;

    /* Создаем контекст ключа KEK */
    // Сравниваем идентификатор ключа из структуры KeyManagementInfo и KEKRI
    if(memcmp(p_kekri->m_key_identifire.mp_value, p_kek->number.data, p_kek->number.size) != 0)
        return ak_error_message(ak_error_invalid_value, __func__, "id from kekri doesn't match id from key management info");

    if((error = pkcs_15_parse_enc_key_plus_mac_seq(p_kekri->m_encrypted_key, &encrypted_cek, &encrypted_cek_mac)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with parsing CEK");

    /*TODO: комментарий для Алексея Юрьевича: здесь необходимо вызвать
            фунцию расшифрования ключа CEK и сравнить имитовставку */

    memcpy((byte*)p_cek->key.data, (byte*)encrypted_cek.data, encrypted_cek.size / 2);
    memcpy((byte*)p_cek->mask.data, (byte*)encrypted_cek.data + encrypted_cek.size / 2, encrypted_cek.size / 2);

    /* Устанавливаем флаги наличия ключа и маски */
    p_cek->flags |= skey_flag_set_key | skey_flag_set_mask;

    /* Перемаскируем ключ */
    if((error = p_cek->set_mask(p_cek)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with key remasking");

    /* Вычисляем контрольную сумму ключа */
    if((error = p_cek->set_icode(p_cek)) != ak_error_ok)
        return ak_error_message(error, __func__, "problem with setting icode");

    /* Устанавливаем флаг наличия контрольной суммы */
    p_cek->flags |= skey_flag_set_icode;

    return ak_error_ok;
}

int write_keys_to_container(struct extended_key** pp_inp_keys, ak_uint8 num_of_inp_keys, ak_pointer password, size_t password_size, byte** pp_out_container, size_t * p_out_container_size) {

    int error;
    struct bckey kek;
    s_pkcs_15_token main_token;
    s_key_management_info* p_kmi;
    size_t token_obj_ind;

    if (!(*pp_inp_keys) || (num_of_inp_keys < 0) || !password || (password_size <= 0))
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    // Создание токена
    memset(&main_token, 0, sizeof(s_pkcs_15_token ));

    // Заполняем верхнюю часть PKCS15Token
    parse_to_integer(&main_token.m_version, 0);

    //Данная реадизация позволяет хранить только один объект KeyManagementInfo, а именно passwordInfo
    main_token.m_info_size = 1;
    main_token.mpp_key_infos = malloc(sizeof(s_key_management_info*) * main_token.m_info_size);


    // Возможно может быть другой ak_bckey_context
    if ((error = ak_bckey_context_create_magma(&kek)) != ak_error_ok) {
        return ak_error_message(error, __func__, "problem with magma context creation");
    }

    p_kmi = (s_key_management_info*) calloc(1, sizeof(s_key_management_info));

    if ((error = put_key_management_info(p_kmi, &kek.key.number)) != ak_error_ok) {
        return ak_error_message(error, __func__, "problem with fill of key management info");
    }

    main_token.mpp_key_infos[0] = p_kmi;

    if ((error = gen_sec_kek_from_pwd(&kek, password, password_size, p_kmi)) != ak_error_ok) {
        return ak_error_message(error, __func__, "generation key from password failed!");
    }

    main_token.mpp_pkcs_15_objects = calloc(num_of_inp_keys, sizeof(s_pkcs_15_object*));
    main_token.m_obj_size = num_of_inp_keys;

    token_obj_ind = 0;

    // Заполняем PKCS15Objects
    for (ak_uint32 i=0; i < num_of_inp_keys; i++) {

        s_pkcs_15_object* current_pkcs15_object = (s_pkcs_15_object*) calloc(1, sizeof(s_pkcs_15_object));

        // Определеяем тип pkcs15_object
        switch (pp_inp_keys[i]->key_type) {
            case PRI_KEY:

                //TODO реализовать

                ak_error_message(ak_error_invalid_value, __func__, "private key support not implemented yet!");
                --main_token.m_obj_size;
                free(current_pkcs15_object);
                current_pkcs15_object = NULL;
                break;

            case PUB_KEY:

                //TODO реализовать

                ak_error_message(ak_error_invalid_value, __func__, "public key support not implemented yet!");
                --main_token.m_obj_size;
                free(current_pkcs15_object);
                current_pkcs15_object = NULL;
                break;

            case SEC_KEY:

                current_pkcs15_object->m_obj.mp_sec_key = (s_gost_sec_key*) calloc(1, sizeof(s_gost_sec_key));
                current_pkcs15_object->m_type = SEC_KEY;

                if ((error = put_gost_secret_key(current_pkcs15_object->m_obj.mp_sec_key, pp_inp_keys[i], &kek)) != ak_error_ok) {
                    return ak_error_message(error, __func__, "problem with fill of gost secret key");
                }

                break;

            default:
                ak_error_message(ak_error_invalid_value, __func__, "unsupported type of object!");
                --main_token.m_obj_size;
                free(current_pkcs15_object);
                current_pkcs15_object = NULL;
                break;
        }

        if (current_pkcs15_object != NULL) {
            main_token.mpp_pkcs_15_objects[token_obj_ind] = current_pkcs15_object;
            ++token_obj_ind;
        }

    }

    // Получаем DER - последовательность
    if ((error = pkcs_15_generate_token(&main_token, pp_out_container, p_out_container_size)) != ak_error_ok) {
        return ak_error_message(error, __func__, "problem with generation of DER sequence");
    }

    // Освобождаем память
    //TODO добавить код возврата
    free_pkcs_15_token(&main_token);

    if ((error = ak_bckey_context_destroy(&kek)) != ak_error_ok) {
        return ak_error_message(error, __func__, "problem with kek destroy");
    }
}
