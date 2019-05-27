#ifndef ASN_1_CONVERSION_COMMONPKCSTYPES_H
#define ASN_1_CONVERSION_COMMONPKCSTYPES_H

#include "kc_asn1_codec.h"
#include "kc_pointer_server.h"
#include "kc_pkcs_algs_and_prms.h"

typedef s_ptr_server s_der_buffer;

typedef enum {
    ENCRYPT = 0x8000u,
    DECRYPT = 0x4000u,
    SIGN = 0x2000u,
    SIGN_RECOVER = 0x1000u,
    WRAP = 0x0800u,
    UNWRAP = 0x0400u,
    VERIFY = 0x0200u,
    VERIFY_RECOVER = 0x0100u,
    DERIVE = 0x0080u,
    NON_REPUDIATION = 0x0040u
} en_usage_bits;

typedef uint16_t key_usage_flags_t;

typedef struct {
    object_identifier m_id;
    void* mp_prms;
} s_algorithm_identifier; //TODO сделать для typedef для GostSecretKeyParameters

typedef struct {
    utf8_string m_label; // добавить ее в extended_keys
    bit_string m_flags; // ???
} s_common_obj_attrs;

typedef struct {
    octet_string m_id; // index + 1 ключа
    bit_string m_usage; // флаг const = encrypt 0xC0, ???
    boolean m_native;
    bit_string m_access_flags; // -
    integer m_key_reference; // -
    generalized_time m_start_date; // добавить в extended keys или вытащить из libakrypt (смотреть формат в kc_asn1_write.c)
    generalized_time m_end_date; // добавить в extended keys или вытащить из libakrypt
} s_common_key_attrs;

typedef struct {
    integer m_version;              // always set to 4
    octet_string m_key_identifire;
    generalized_time m_date;
    //s_algorithm_identifier* mp_key_enc_alg; //TODO удалить
    object_identifier m_key_enc_alg_id;
    octet_string m_encrypted_key;
    en_param_set_type m_prm_set_type;
    u_param_set m_prm_set;
}s_kekri;

/*
 * Содержит как вариант для password info
 * (используемый в key management info),
 * так и recipient info;
 * Значения соответствуют тегам из стандарта
 */
typedef enum {
    PWD_INFO = 0u,
    KEKRI    = 2u,
    PWRI     = 3u
} en_pr_info;

typedef union {
    s_kekri* mp_kekri;
    //TODO: Добавить вариант Password Recipient Info;
} u_recipient_info;

typedef struct {
    en_pr_info m_type;
    u_recipient_info m_ri;
}s_recipient_info;

typedef struct {
    integer m_version;
    s_recipient_info** mpp_recipient_infos;
    uint8_t m_ri_size;
    object_identifier m_content_type;
    //s_algorithm_identifier* mp_content_enc_alg;
    object_identifier m_content_enc_alg_id;
    en_param_set_type m_prm_set_type;
    u_param_set m_prm_set;
    octet_string m_encrypted_content;
}s_enveloped_data;

/* В данной версии не используется */
typedef struct {
    s_algorithm_identifier* mp_parameters; //const "1.2.643.7.1.2.5.1.1"
    bit_string m_supported_operations; // 0
}s_key_info;

int pkcs_15_put_object_direct_protected(s_der_buffer *p_pkcs_15_token, s_enveloped_data *p_enveloped_data, s_der_buffer *p_enveloped_data_der);

int pkcs_15_put_common_object_attributes(s_der_buffer *p_pkcs_15_token, s_common_obj_attrs *p_obj_attrs, s_der_buffer *p_common_object_attributes_der);
int pkcs_15_put_common_key_attributes(s_der_buffer *p_pkcs_15_token, s_common_key_attrs *p_key_attrs, s_der_buffer *p_common_key_attributes_der);

int pkcs_15_put_recipient_infos(s_der_buffer *p_pkcs_15_token, s_recipient_info **pp_recipient_infos, uint8_t num_of_recipient_infos, s_der_buffer *p_recipient_infos_der);
int pkcs_15_put_single_recipient_info(s_der_buffer *p_pkcs_15_token, s_recipient_info *p_sngl_recipient_info, s_der_buffer *p_sngl_recipient_info_der);
int pkcs_15_put_kekri(s_der_buffer *p_pkcs_15_token, s_kekri *p_kekri, s_der_buffer *p_kekri_der);
int pkcs_15_put_key_encryption_algorithm(s_der_buffer *p_pkcs_15_token, s_kekri *p_kekri, s_der_buffer *p_key_encryption_algorithm_der);

int pkcs_15_put_encrypted_content_info(s_der_buffer *p_pkcs_15_token, s_enveloped_data *p_enveloped_data, s_der_buffer *p_encrypted_content_info_der);
int pkcs_15_put_content_encryption_algorithm(s_der_buffer *p_pkcs_15_token, s_enveloped_data *p_enveloped_data, s_der_buffer *p_content_enc_alg_der);

int pkcs_15_get_object_direct_protected(s_der_buffer *p_object_der, s_enveloped_data *p_enveloped_data);

int pkcs_15_get_common_object_attributes(s_der_buffer *p_object_der, s_common_obj_attrs *p_obj_attrs);
int pkcs_15_get_common_key_attributes(s_der_buffer *p_object_der, s_common_key_attrs *p_key_attrs);

int pkcs_15_get_recipient_infos(s_der_buffer *p_enveloped_data_der, s_enveloped_data* p_enveloped_data);
int pkcs_15_get_sngl_recipient_info(s_der_buffer *p_recipient_infos_der, s_recipient_info* p_sngl_recipient_info);
int pkcs_15_get_kekri(s_der_buffer *p_recipient_infos_der, s_kekri *p_kekri);
int pkcs_15_get_key_encryption_algorithm(s_der_buffer *p_kekri_der, s_kekri *p_kekri);

int pkcs_15_get_encrypted_content_info(s_der_buffer *p_enveloped_data_der, s_enveloped_data* p_enveloped_data);
int pkcs_15_get_content_encryption_algorithm(s_der_buffer *p_encrypted_content_info_der, s_enveloped_data* p_enveloped_data);

void pkcs_15_free_key_info(s_key_info* p_ki);
void pkcs_15_free_enveloped_data(s_enveloped_data* p_ed);
void pkcs_15_free_recipient_info(s_recipient_info* p_ri);
void pkcs_15_free_kekri(s_kekri* p_kekri);
void pkcs_15_free_common_key_attrs(s_common_key_attrs* p_cka);
void pkcs_15_free_common_obj_attrs(s_common_obj_attrs* p_coa);

#endif /* ASN_1_CONVERSION_COMMONPKCSTYPES_H */

