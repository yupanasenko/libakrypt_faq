#ifndef ASN_1_CONVERSION_PKCSCONTAINER_H
#define ASN_1_CONVERSION_PKCSCONTAINER_H

#include "ak_pkcs_15_gost_secret_key.h"

typedef enum {
    PRI_KEY = 0,
    PUB_KEY = 1,
    SEC_KEY = 3
} en_obj_type;

typedef union {
    s_gost_sec_key* mp_sec_key;
    // TODO: добавить private key и public key
} u_pkcs_15_object;

typedef struct {
    en_obj_type m_type;
    u_pkcs_15_object m_obj;
} s_pkcs_15_object;

typedef struct {
    utf8_string m_hint;
    object_identifier m_algorithm;
    octet_string m_salt;
    integer m_iteration_count;
    integer m_key_len;
    object_identifier m_prf_id; // todo: Возможно, лучше сделать отдельный тип AlgoritmIdentifire
}s_pwd_info;

typedef union {
    s_pwd_info* mp_pwd_info;
    s_kekri* mp_kekri;
    // TODO: Добавить вариант Password Recipient Info;
} u_key_info_kmi;

typedef struct {
    octet_string m_key_id;
    en_pr_info m_type;
    u_key_info_kmi m_key_info;
} s_key_management_info;

typedef struct {
    integer m_version;
    s_key_management_info** mpp_key_infos;
    uint8_t m_info_size;
    s_pkcs_15_object** mpp_pkcs_15_objects;
    uint8_t m_obj_size;
}s_pkcs_15_token;

int pkcs_15_generate_token(s_pkcs_15_token *p_pkcs_15_token, byte **pp_data, size_t *p_size);
int pkcs_15_put_pkcs_objects(s_der_buffer *p_pkcs_15_token, s_pkcs_15_object **pp_pkcs_15_objects, int8_t size, s_der_buffer *p_pkcs_15_object_der);
int pkcs_15_put_obj(s_der_buffer *p_pkcs_15_token, s_pkcs_15_object *p_pkcs_15_object, s_der_buffer *p_added_pkcs_15_object_der);
int pkcs_15_put_obj_direct(s_der_buffer *p_pkcs_15_token, s_pkcs_15_object *p_pkcs_15_object, s_der_buffer *p_direct_pkcs_15_object_der);

int pkcs_15_put_key_management_info(s_der_buffer *p_pkcs_15_token, s_key_management_info *p_key_management_info, s_der_buffer *p_key_management_info_der);
int pkcs_15_put_password_info(s_der_buffer *p_pkcs_15_token, s_pwd_info *p_pwd_info, s_der_buffer *p_pwd_info_der);
int pkcs_15_put_alg_id(s_der_buffer *p_pkcs_15_token, s_pwd_info *p_pwd_info, s_der_buffer *p_alg_id_der);
int pkcs_15_put_params_pbkdf2(s_der_buffer *p_pkcs_15_token, s_pwd_info *p_pwd_info, s_der_buffer *p_parameters_der);


int pkcs_15_parse_token(byte *p_data, size_t size, s_pkcs_15_token *p_pkcs_15_token);
int pkcs_15_get_key_management_info(s_der_buffer *p_pkcs_15_token_der, s_pkcs_15_token *p_pkcs_15_token);
int pkcs_15_get_sngl_kmi(s_der_buffer *p_key_management_info_der, s_pkcs_15_token *p_pkcs_15_token);
int pkcs_15_get_password_info(s_der_buffer *p_sngl_kmi_der, s_pwd_info *p_pwd_info);
int pkcs_15_get_alg_id(s_der_buffer *p_pwd_info_der, s_pwd_info *p_pwd_info);
int pkcs_15_get_params_pbkdf2(s_der_buffer *p_alg_id_der, s_pwd_info *p_pwd_info);

int pkcs_15_get_pkcs_objects(s_der_buffer *p_pkcs_15_token_der, s_pkcs_15_token *p_pkcs_15_token);
int pkcs_15_get_obj(s_der_buffer *p_pkcs_15_objects_der, s_pkcs_15_object *p_pkcs_15_object);
int pkcs_15_get_direct_obj(s_der_buffer *p_pkcs_15_object_der, s_pkcs_15_object *p_pkcs_15_object);


void print_ps(s_ptr_server* p_ps);

void free_pkcs_15_token(s_pkcs_15_token* p_pkcs_15_token);
void free_key_management_info(s_key_management_info* p_kmi);
void free_pwd_info(s_pwd_info* p_pwd_info);
void free_pkcs_15_object(s_pkcs_15_object* p_object);

#endif //ASN_1_CONVERSION_PKCSCONTAINER_H
