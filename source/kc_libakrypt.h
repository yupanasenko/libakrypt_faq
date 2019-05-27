#ifndef ASN_1_CONVERSION_KC_LIBAKRYPT_H
#define ASN_1_CONVERSION_KC_LIBAKRYPT_H


#include "kc_asn1_codec.h"
#include "kc_pkcs_gost_secret_key.h"
#include "ak_bckey.h"
#include "kc_pkcs_container.h"
#include "kc_pkcs_gost_secret_key.h"

typedef unsigned int date[6];

#include "kc_tools.h"
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

static int get_extended_key(s_pkcs_15_object* p_obj, struct skey* p_kek, struct extended_key* p_key);
static int decrypt_enveloped_data(s_enveloped_data* p_enveloped_data, ak_skey p_kek, ak_skey p_libakrypt_key);
static int decrypt_content_enc_key(s_recipient_info* p_recipient_info, ak_skey p_kek, ak_skey p_cek);

/**
 *
 * @param pp_inp_keys
 * @param num_of_inp_keys
 * @param pp_out_container - DER последовательность.
 * @param p_out_container_size
 * @return
 */
int write_keys_to_container(struct extended_key** pp_inp_keys, ak_uint8 num_of_inp_keys, ak_pointer password, size_t password_size, byte** pp_out_container, size_t * p_out_container_size);





#endif //ASN_1_CONVERSION_KC_LIBAKRYPT_H



