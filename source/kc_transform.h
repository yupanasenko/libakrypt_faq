//
// Created by gerg on 2019-05-17.
//

#ifndef ASN_1_CONVERSION_KC_TRANSFORM_H
#define ASN_1_CONVERSION_KC_TRANSFORM_H


#include "kc_libakrypt.h"

int put_key_management_info(s_key_management_info* current_key_info, ak_buffer key_id);

int fill_enveloped_data(ak_skey sec_key, s_enveloped_data *enveloped_data, ak_bckey kek);

int put_gost_secret_key(s_gost_sec_key* gost_sec_key, struct extended_key* p_inp_keys, ak_bckey kek);

#endif //ASN_1_CONVERSION_KC_TRANSFORM_H
