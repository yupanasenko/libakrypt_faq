//
// Created by gerg on 2019-05-15.
//


#ifndef ASN_1_CONVERSION_KC_TOOLS_H
#define ASN_1_CONVERSION_KC_TOOLS_H

#include <ak_skey.h>
#include "kc_asn1_codec.h"
#include "kc_includes.h"
#include "kc_libakrypt.h"

int parse_to_boolean(boolean* p_asn_1_bool, bool val);

int parse_to_utf8_string(utf8_string* p_asn_1_utf8_string, ak_pointer p_val);

int parse_to_visible_string(visible_string* p_asn_1_visible_string, const char* p_val);

int parse_to_generalized_time(generalized_time* p_asn_1_generalized_time, const char* p_val);

int parse_to_object_identifier(object_identifier* p_asn_1_object_identifier, const char* p_val);

int parse_to_integer(integer* p_asn_int, int32_t val);

int parse_to_bit_string(bit_string* p_asn_1_bit_string, const byte* p_val, uint32_t size, uint8_t num_of_unused_bits);

int parse_to_octet_string(octet_string* p_asn_1_octet_string, const byte* p_val, uint32_t size);


int parse_date_to_generalized_time(date current_date, generalized_time* result);

int asn_integer_to_int64(integer* p_asn_val, ak_int64* p_value);

int asn_utf8_to_byte_arr(utf8_string* p_src, byte** pp_dst);

int asn_generalized_time_to_date(generalized_time time, date date);

int set_usage_flags(bit_string asn_val, key_usage_flags_t* flags);

int set_key_id(octet_string id, ak_skey p_key);

int pkcs_15_prepare_gost_key_for_enc(ak_skey gost_key, ak_buffer gost_key_der);

int generate_random_bytes(octet_string* p_data, const size_t size);

char* key_usage_flags_to_str(key_usage_flags_t flags);

void print_ak_buffer(ak_buffer p_buff);

#endif //ASN_1_CONVERSION_KC_TOOLS_H
