//
// Created by Anton Sakharov on 2019-05-25.
//

#ifndef ASN_1_CONVERSION_KC_KEY_MANAGER_H
#define ASN_1_CONVERSION_KC_KEY_MANAGER_H

#include <ak_bckey.h>
#include "kc_pkcs_container.h"

/*! \brief Выработка секретного ключа (KEK) на основе пароля */
int gen_sec_kek_from_pwd(ak_bckey p_key, ak_pointer password, size_t pwd_len, s_key_management_info* p_kmi);

#endif //ASN_1_CONVERSION_KC_KEY_MANAGER_H
