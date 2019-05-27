//
// Created by Anton Sakharov on 2019-05-25.
//

#include "kc_key_manager.h"
#include <ak_tools.h>
#include "kc_tools.h"

int gen_sec_kek_from_pwd(ak_bckey p_key, ak_pointer password, size_t pwd_len, s_key_management_info* p_kmi)
{
    int error;
    ak_int64 iteration_cnt;
    ak_int64 key_len;
    s_pwd_info* p_pwd_info;

    if(p_kmi->m_type != PWD_INFO)
        return ak_error_message(ak_error_invalid_value, __func__, "only key management info with password info support");

    p_pwd_info = p_kmi->m_key_info.mp_pwd_info;

    if((strcmp(p_pwd_info->m_algorithm, "1.2.840.113549.1.5.12") != 0)
        || (strcmp(p_pwd_info->m_prf_id, "1.2.643.7.1.1.4.2") != 0))
    {
        return ak_error_message(ak_error_invalid_value, __func__, "unallowed algorithm");
    }

    if(!p_pwd_info->m_iteration_count.mp_value)
        return ak_error_message(ak_error_invalid_value, __func__, "iteration count absent");

    /* Устанавливаем длину ключа (если в контейнере есть значение, то записываем его, иначе устанавливаем константное) */
    key_len = 32;
    if(p_pwd_info->m_key_len.mp_value)
    {
        if ((error = asn_integer_to_int64(&p_pwd_info->m_key_len, &key_len)) != ak_error_ok)
            return ak_error_message(error, __func__, "can't get key length");
    }

//    /* Создаем контекст секретного ключа */
//    if((error = ak_skey_context_create(p_key, (size_t)key_len, 8)) != ak_error_ok)
//        return ak_error_message(error, __func__, "can't create secret key context");

    /* Присваиваем ключу идентификатор, указанный в поле keyId структуры KeyManagementInfo */
    set_key_id(p_kmi->m_key_id, &p_key->key);

    /* Устанвливаем кол-во итераций */
    if((error = asn_integer_to_int64(&p_pwd_info->m_iteration_count, &iteration_cnt)) != ak_error_ok)
        return ak_error_message(error, __func__, "can't get iteration count");

    if((error = ak_libakrypt_set_option("pbkdf2_iteration_count", iteration_cnt)) != ak_error_ok)
        return ak_error_message(error, __func__, "can't set iteration count value");

    /* Генерируем ключ */
    if((error = ak_bckey_context_set_key_from_password(p_key, password, pwd_len, p_pwd_info->m_salt.mp_value, p_pwd_info->m_salt.m_val_len)) != ak_error_ok)
        return ak_error_message(error, __func__, "can't create key from password");

    return ak_error_ok;
}
