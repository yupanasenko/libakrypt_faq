//
// Created by Anton Sakharov on 2019-04-17.
//

#ifndef ASN_1_CONVERSION_KC_PKCS_ALGS_AND_PRMS_H
#define ASN_1_CONVERSION_KC_PKCS_ALGS_AND_PRMS_H

#include "kc_pkcs_common_types.h"

typedef enum {
    GOST_CONTENT_ENC_SET = 1, // соответствует структуре s_gost28147_89_prms
    GOST_KEY_WRAP_SET    = 2, // соответствует структуре s_gost28147_89_key_wrap_prms
} en_param_set_type;

typedef struct {
    octet_string m_iv;
    object_identifier m_encryption_param_set;
} s_gost28147_89_prms;

typedef struct {
    object_identifier m_enc_prm_set;
    octet_string m_ukm;
} s_gost28147_89_key_wrap_prms;

typedef union {
    s_gost28147_89_prms* p_content_enc_prm_set;
    s_gost28147_89_key_wrap_prms* p_key_wrap_set;
} u_param_set;

/* В данной версии не используется */
//typedef struct {
//    octet_string m_e_uz;
//    integer m_mode;
//    integer m_shift_bits;
//    s_algorithm_identifier* mp_key_meshing;
//} s_gost28147_89_param_set_parameters;


void pkcs_15_free_gost28147_89_prms(s_gost28147_89_prms* p_prms);

#endif //ASN_1_CONVERSION_KC_PKCS_ALGS_AND_PRMS_H
