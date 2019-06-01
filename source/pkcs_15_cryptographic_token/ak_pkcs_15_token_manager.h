#ifndef ASN_1_CONVERSION_KC_LIBAKRYPT_H
#define ASN_1_CONVERSION_KC_LIBAKRYPT_H


#include "ak_asn_codec.h"
#include "ak_pkcs_15_gost_secret_key.h"
#include "ak_bckey.h"
#include "ak_pkcs_15_token.h"
#include "ak_pkcs_15_gost_secret_key.h"

typedef unsigned int date[6];

#include <ak_context_manager.h>


/**
 * (secret or private or public) form libakrypt key
 */
union kc_key {
    ak_bckey sec_key;
    // TODO Добавить структуры для private/public keys
};

/** Расширение структуры ключей (secret, private, public)
 * добавление label
 *
 */
struct extended_key {
    union kc_key key;
    en_obj_type key_type; // enPrivKey = 0, enPubKey = 1, enSecKey = 3
    ak_pointer label;
    date start_date;
    date end_date; //TODO заменить на date в функции
    key_usage_flags_t flags;
};


/**
 *
 * @param password
 * @param pwd_size
 * @param inp_container
 * @param inp_container_size
 * @param out_keys
 * @param num_of_out_keys
 * @return
 */
int read_keys_from_container(byte* password, size_t pwd_size, byte* inp_container, size_t inp_container_size, struct extended_key*** out_keys, ak_uint8* num_of_out_keys);

/**
 *
 * @param pp_inp_keys
 * @param num_of_inp_keys
 * @param pp_out_container - DER последовательность.
 * @param p_out_container_size
 * @return
 */
int write_keys_to_container(struct extended_key** pp_inp_keys, ak_uint8 num_of_inp_keys, ak_pointer password, size_t password_size, byte** pp_out_container, size_t * p_out_container_size);


char* key_usage_flags_to_str(key_usage_flags_t flags);



#endif //ASN_1_CONVERSION_KC_LIBAKRYPT_H



