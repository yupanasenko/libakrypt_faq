//
// Created by gerg on 2019-05-17.
//

#include <kc_tools.h>
#include "kc_transform.h"
#include <ak_context_manager.h>
#include <ak_tools.h>

const object_identifier ALGORITHM_PBKDF2 = {"1.2.840.113549.1.5.12"};
const object_identifier HMAC_GOST_3411_12_512 = {"1.2.643.7.1.1.4.2"};
const object_identifier CRYPTO_PRO_PARAM_SET = {"1.2.643.7.1.2.5.1.1"};
const object_identifier KEY_TYPE_GOST = {"1.2.643.7.1.1.5.1"};
const object_identifier KEY_ENG_ALGORITHM = {"1.2.643.2.2.13.1"};
const object_identifier CONTENT_TYPE = {"1.2.840.113549.1.7.1"};
const object_identifier CONTENT_ENG_ALGORITHM = {"1.2.643.2.4.3.2.2"};
const object_identifier CRYPTO_PRO_PARAM_A = {"1.2.643.2.2.31.1"};

int put_key_management_info(s_key_management_info *current_key_info, ak_buffer key_id) {

    int error;
    ak_int64 pbkdf2_iteration_count; // значение номера для pbkdf2_iteration_count
    s_pwd_info *pwd_info; // структура passwordInfo

    if (!current_key_info || !key_id)
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");

    pwd_info = calloc(1, sizeof(s_pwd_info));

    // TODO Заполняем hint (если нужно необходимо добавить)

    parse_to_object_identifier(&pwd_info->m_algorithm, ALGORITHM_PBKDF2);

    if ((error = generate_random_bytes(&pwd_info->m_salt, 8)) != ak_error_ok) {
        return ak_error_message(error, __func__, "problem with salt generation");
    }

    pbkdf2_iteration_count = ak_libakrypt_get_option("pbkdf2_iteration_count");
    parse_to_integer(&pwd_info->m_iteration_count, pbkdf2_iteration_count);

    parse_to_integer(&pwd_info->m_key_len, 32); // Всегда 32

    parse_to_object_identifier(&pwd_info->m_prf_id, HMAC_GOST_3411_12_512);

    parse_to_octet_string(&current_key_info->m_key_id, key_id->data, key_id->size);

    current_key_info->m_type = PWD_INFO;
    current_key_info->m_key_info.mp_pwd_info = pwd_info;

    return ak_error_ok;
}

int put_gost_secret_key(s_gost_sec_key *gost_sec_key, struct extended_key *p_inp_keys, ak_bckey kek) {

    if (!gost_sec_key || !p_inp_keys || !kek) {
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");
    }

    int error;
    s_common_obj_attrs obj_attrs;
    s_common_key_attrs common_key_attrs;
    byte key_usage_flags[2] = {(byte) ((p_inp_keys->flags >> 8) & 0xFFu), (byte) (p_inp_keys->flags & 0xFF)};

    // CommonObjectAttributes
    memset(&obj_attrs, 0, sizeof(obj_attrs));
    // Заполняем label
    parse_to_utf8_string(&obj_attrs.m_label, p_inp_keys->label);

    // Записываем в s_gost_sec_key
    gost_sec_key->m_obj_attrs = obj_attrs;

    // CommonKeyAttributes
    memset(&common_key_attrs, 0, sizeof(s_common_key_attrs));

    // Заполняем iD
    parse_to_octet_string(&common_key_attrs.m_id, p_inp_keys->key.sec_key->key.number.data,
                          p_inp_keys->key.sec_key->key.number.size);

    // Заполняем usage
    parse_to_bit_string(&common_key_attrs.m_usage, key_usage_flags, sizeof(key_usage_flags), 6);

    // Заполняем native константным значением
    parse_to_boolean(&common_key_attrs.m_native, true);

    // Заполняем startDate
    parse_date_to_generalized_time(p_inp_keys->start_date, &common_key_attrs.m_start_date);

    // Заполняем endDate
    parse_date_to_generalized_time(p_inp_keys->end_date, &common_key_attrs.m_end_date);

    // Записываем в s_gost_sec_key
    gost_sec_key->m_key_attrs = common_key_attrs;


    parse_to_object_identifier(&gost_sec_key->m_key_type_gost, KEY_TYPE_GOST);

    if ((error = fill_enveloped_data(&p_inp_keys->key.sec_key->key, &gost_sec_key->m_enveloped_data, kek)) != ak_error_ok) {
        return ak_error_message(error, __func__, "problem with fill of enveloped data");
    }

    return ak_error_ok;
}


int fill_enveloped_data(ak_skey sec_key, s_enveloped_data *enveloped_data, ak_bckey kek) {

    int error;
    ak_context_manager p_context;
    struct bckey cek;
    struct buffer gost_key_der;
    byte mac[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    s_gost28147_89_prms *p_content_enc_prms;
    octet_string iv;
    s_kekri *kekri;
    s_gost28147_89_key_wrap_prms *p_key_wrap_prms;
    byte ukm[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    struct buffer cek_plus_mask;
    struct buffer encrypted_key_mac;
    struct buffer encrypted_key_der;
    s_recipient_info **recipient_infos;
    s_recipient_info *recipient_info;
    uint8_t recipient_infos_size = 1;

    if (!sec_key || !enveloped_data || !kek) {
        return ak_error_message(ak_error_null_pointer, __func__, "invalid arguments");
    }

    // Заполняем version
    parse_to_integer(&enveloped_data->m_version, 2);

    // Создаем Content Encryption Key

    if ((error = ak_bckey_context_create_magma(&cek)) != ak_error_ok) {
        return ak_error_message(error, __func__, "problem with magma context creation");
    }

    p_context = ak_libakrypt_get_context_manager();

    if ((error = ak_bckey_context_set_key_random(&cek, &p_context->key_generator)) != ak_error_ok) {
        return ak_error_message(error, __func__, "problem with cek generation");
    }

    // Подготоваливаем даннные к шифрованию

    if ((error = ak_buffer_create(&gost_key_der)) != ak_error_ok) {
        return ak_error_message(error, __func__, "problem with ak buffer creation");
    }

    if ((error = pkcs_15_make_gost_key_value_mask(&sec_key->key, &sec_key->mask, sec_key->resource.counter, &gost_key_der)) != ak_error_ok) {
        return ak_error_message(error, __func__, "problem with gost key mask setting");
    }


    // Зашифровываем подготовленную DER - последовательность и считаем имитовставку
    //TODO вызываем фнукцию шифрования gost_key_der
    //TODO добавляем имитовставку (mac var)

    // Заполняем encryptedContentInfo

    // Заполняем encryptedContent
    enveloped_data->m_encrypted_content.m_val_len = gost_key_der.size + sizeof(mac);
    enveloped_data->m_encrypted_content.mp_value = (byte *) malloc(enveloped_data->m_encrypted_content.m_val_len);

    if (!enveloped_data->m_encrypted_content.mp_value) {
        return ak_error_null_pointer;
    }

    memcpy(enveloped_data->m_encrypted_content.mp_value, gost_key_der.data, gost_key_der.size);
    memcpy(enveloped_data->m_encrypted_content.mp_value + gost_key_der.size, mac, sizeof(mac));

    if ((error = ak_buffer_destroy(&gost_key_der)) != ak_error_ok) {
        return ak_error_message(error, __func__, "problem with buffer destroy");
    }

    // Заполняем contentEncryptionAlgorithm
    parse_to_object_identifier(&enveloped_data->m_content_enc_alg_id, CONTENT_ENG_ALGORITHM);
    p_content_enc_prms = calloc(1, sizeof(s_gost28147_89_prms));

    if ((error = generate_random_bytes(&iv, 8)) != ak_error_ok) {
        return ak_error_message(error, __func__, "problem with iv generation");
    }

    parse_to_octet_string(&p_content_enc_prms->m_iv, iv.mp_value, iv.m_val_len);
    parse_to_object_identifier(&p_content_enc_prms->m_encryption_param_set, CRYPTO_PRO_PARAM_A);

    enveloped_data->m_prm_set_type = GOST_CONTENT_ENC_SET;
    enveloped_data->m_prm_set.p_content_enc_prm_set = p_content_enc_prms;

    // Заполняем contentType
    parse_to_object_identifier(&enveloped_data->m_content_type, CONTENT_TYPE);

    // Заполняем recipientInfos

    // Kekri
    kekri = calloc(1, sizeof(s_kekri));

    parse_to_integer(&kekri->m_version, 4); // всегда равно 4 по стандарту RFC-5652

    parse_to_octet_string(&kekri->m_key_identifire, kek->key.number.data, kek->key.number.size);

    parse_to_object_identifier(&kekri->m_key_enc_alg_id, KEY_ENG_ALGORITHM);
    p_key_wrap_prms = calloc(1, sizeof(s_gost28147_89_key_wrap_prms));

    //TODO добавляем значения для wrapping
    // TODO заменить на реальное значение ukm
    parse_to_octet_string(&p_key_wrap_prms->m_ukm, ukm, sizeof(ukm));
    parse_to_object_identifier(&p_key_wrap_prms->m_enc_prm_set, CRYPTO_PRO_PARAM_A);


    kekri->m_prm_set_type = GOST_KEY_WRAP_SET;
    kekri->m_prm_set.p_key_wrap_set = p_key_wrap_prms;

    // Шифруем CEK при помощи KEK

    if ((error = ak_buffer_create_size(&cek_plus_mask, cek.key.key.size + cek.key.mask.size)) != ak_error_ok) {
        return ak_error_message(error, __func__, "problem with cek + mask buffer creation");
    }

    memcpy(cek_plus_mask.data, cek.key.key.data, cek.key.key.size);
    memcpy((byte *) cek_plus_mask.data + cek.key.key.size, cek.key.mask.data, cek.key.mask.size);

    // TODO Заменить на реальное значение

    if ((error = ak_buffer_create(&encrypted_key_mac)) != ak_error_ok) {
        return ak_error_message(error, __func__, "problem with encrypted key mac buffer creation");
    }

    encrypted_key_mac.data = mac;
    encrypted_key_mac.size = sizeof(mac);

    if ((error = ak_buffer_create(&encrypted_key_der)) != ak_error_ok) {
        return ak_error_message(error, __func__, "problem with encrypted key der buffer creation");
    }

    if ((error = pkcs_15_make_enc_key_plus_mac_seq(&cek_plus_mask, &encrypted_key_mac, &encrypted_key_der)) != ak_error_ok) {
        return ak_error_message(error, __func__, "problem with encrypted key + mac sequence creation");
    }

    if ((error = ak_buffer_destroy(&cek_plus_mask)) != ak_error_ok) {
        return ak_error_message(error, __func__, "problem with cek + mask buffer destroy");
    }

    if ((error = ak_buffer_destroy(&encrypted_key_mac)) != ak_error_ok) {
        return ak_error_message(error, __func__, "problem with encrypted key mac buffer destroy");
    }

    parse_to_octet_string(&kekri->m_encrypted_key, encrypted_key_der.data, encrypted_key_der.size);

    if ((error = ak_buffer_destroy(&encrypted_key_der)) != ak_error_ok) {
        return ak_error_message(error, __func__, "problem with encrypted key der buffer destroy");
    }

    recipient_info = malloc(sizeof(s_recipient_info));// = {KEKRI, &kekri};

    recipient_info->m_type = KEKRI;
    recipient_info->m_ri.mp_kekri = kekri;

    //Данная реадизация позволяет хранить только один объект recipientInfo, а именно KEKRI
    recipient_infos = malloc(sizeof(s_recipient_info *) * recipient_infos_size);
    recipient_infos[0] = recipient_info;

    enveloped_data->mpp_recipient_infos = recipient_infos;
    enveloped_data->m_ri_size = recipient_infos_size;

    if ((error = ak_bckey_context_destroy(&cek)) != ak_error_ok) {
        return ak_error_message(error, __func__, "problem with cek destroy");
    }

    return ak_error_ok;
}
