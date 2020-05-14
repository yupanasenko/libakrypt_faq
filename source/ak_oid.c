/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2020 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Файл ak_oid.с                                                                                  */
/*  - содержит реализации функций для работы с идентификаторами криптографических                  */
/*    алгоритмов и параметров                                                                      */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_parameters.h>

#ifdef LIBAKRYPT_CRYPTO_FUNCTIONS
 #include <ak_hmac.h>
 #include <ak_bckey.h>
 #include <ak_sign.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_STRING_H
 #include <string.h>
#else
 #error Library cannot be compiled without string.h header
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! Константные значения имен идентификаторов */
 static const char *on_lcg[] =              { "lcg", NULL };
#if defined(__unix__) || defined(__APPLE__)
 static const char *on_dev_random[] =       { "dev-random", "/dev/random", NULL };
 static const char *on_dev_urandom[] =      { "dev-urandom", "/dev/urandom", NULL };
#endif
#ifdef _WIN32
 static const char *on_winrtl[] =           { "winrtl", NULL };
#endif

#ifdef LIBAKRYPT_CRYPTO_FUNCTIONS
 static const char *on_hashrnd[] =          { "hashrnd", NULL };
 static const char *on_streebog256[] =      { "streebog256", "md_gost12_256", NULL };
 static const char *on_streebog512[] =      { "streebog512", "md_gost12_512", NULL };
 static const char *on_hmac_streebog256[] = { "hmac-streebog256", "HMAC-md_gost12_256", NULL };
 static const char *on_hmac_streebog512[] = { "hmac-streebog512", "HMAC-md_gost12_512", NULL };

 static const char *on_kuznechik[] =        { "kuznechik", "kuznyechik", "grasshopper", NULL };
 static const char *on_magma[] =            { "magma", NULL };

 static const char *on_sign256[] =          { "id-tc26-signwithdigest-gost3410-12-256",
                                              "sign256", NULL };
 static const char *on_sign512[] =          { "id-tc26-signwithdigest-gost3410-12-512",
                                              "sign512", NULL };
 static const char *on_verify256[] =        { "id-tc26-gost3410-12-256", "verify256", NULL };
 static const char *on_verify512[] =        { "id-tc26-gost3410-12-512", "verify512", NULL };
#endif

 static const char *on_w256_pst[] =         { "id-tc26-gost-3410-2012-256-paramSetTest", NULL };
 static const char *on_w256_psa[] =         { "id-tc26-gost-3410-2012-256-paramSetA", NULL };
 static const char *on_w256_psb[] =         { "id-tc26-gost-3410-2012-256-paramSetB", NULL };
 static const char *on_w256_ps4357a[] =     { "id-rfc4357-gost-3410-2001-paramSetA",
                                              "cspa", NULL };
 static const char *on_w256_psc[] =         { "id-tc26-gost-3410-2012-256-paramSetC", NULL };
 static const char *on_w256_ps4357b[] =     { "id-rfc4357-gost-3410-2001-paramSetB",
                                              "cspb", NULL };
 static const char *on_w256_psd[] =         { "id-tc26-gost-3410-2012-256-paramSetD", NULL };
 static const char *on_w256_ps4357c[] =     { "id-rfc4357-gost-3410-2001-paramSetC",
                                              "cspc", NULL };
 static const char *on_w256_ps4357d[] =     { "id-rfc4357-2001dh-paramSet",
                                              "cspdh", NULL };
 static const char *on_w512_pst[] =         { "id-tc26-gost-3410-2012-512-paramSetTest", NULL };
 static const char *on_w512_psa[] =         { "id-tc26-gost-3410-2012-512-paramSetA", NULL };
 static const char *on_w512_psb[] =         { "id-tc26-gost-3410-2012-512-paramSetB", NULL };
 static const char *on_w512_psc[] =         { "id-tc26-gost-3410-2012-512-paramSetC", NULL }; 
 static const char *on_w256_axel[] =        { "id-axel-gost-3410-2012-256-paramSetN0",
                                              "axel-n0", NULL };
#ifdef LIBAKRYPT_CRYPTO_FUNCTIONS
 static const char *on_asn1_akcont[] =      { "libakrypt-container", NULL };
 static const char *on_asn1_pbkdf2key[] =   { "pbkdf2-basic-key", NULL };
 static const char *on_asn1_sdhkey[] =      { "static-dh-basic-key", NULL };
 static const char *on_asn1_extkey[] =      { "external-basic-key", NULL };

 static const char *on_asn1_symkmd[] =      { "symmetric-key-content", NULL };
 static const char *on_asn1_skmd[] =        { "secret-key-content", NULL };
 static const char *on_asn1_pkmd[] =        { "public-key-content", NULL };
 static const char *on_asn1_ecmd[] =        { "encrypted-content", NULL };
 static const char *on_asn1_pcmd[] =        { "plain-content", NULL };

 static const char *on_asn1_ogrn[] =        { "OGRN", NULL };
 static const char *on_asn1_snils[] =       { "SNILS", NULL };
 static const char *on_asn1_ogrnip[] =      { "OGRNIP", NULL };
 static const char
                *on_asn1_owners_module[] =  { "SubjectsCryptoModule", NULL };
 static const char
                *on_asn1_issuers_module[] = { "IssuersCryptoModule", NULL };
 static const char *on_asn1_inn[] =         { "INN", NULL };
 static const char *on_asn1_email[] =       { "emailAddress", "email", NULL };
 static const char *on_asn1_cn[] =          { "CommonName", "CN", NULL };
 static const char *on_asn1_s[] =           { "Surname", "S", NULL };
 static const char *on_asn1_sn[] =          { "SerialNumber", "SN", NULL };
 static const char *on_asn1_c[] =           { "CountryName", "C", NULL };
 static const char *on_asn1_l[] =           { "LocalityName", "L", NULL };
 static const char *on_asn1_st[] =          { "StateOrProvinceName", "ST", NULL };
 static const char *on_asn1_sa[] =          { "StreetAddress", "SA", NULL };
 static const char *on_asn1_o[] =           { "Organization", "O", NULL };
 static const char *on_asn1_ou[] =          { "OrganizationUnit", "OU", NULL };

 static const char *on_asn1_ku[] =          { "Key Usage", NULL };
 static const char *on_asn1_ski[] =         { "SubjectKey Identifier", NULL };
 static const char *on_asn1_bc[] =          { "Basic Constraints", NULL };
 static const char *on_asn1_cp[] =          { "Certificate Policies", NULL };
 static const char *on_asn1_wcp[] =         { "Wildcard Certificate Policy", NULL };
 static const char *on_asn1_aki[] =         { "AuthorityKey Identifier", NULL };

/* Приказ ФСБ N-795*/
 static const char *on_asn1_class_kc1[] =   { "Digital Signature Module, class KC1", NULL };
 static const char *on_asn1_class_kc2[] =   { "Digital Signature Module, class KC2", NULL };
 static const char *on_asn1_class_kc3[] =   { "Digital Signature Module, class KC3", NULL };
 static const char *on_asn1_class_kb1[] =   { "Digital Signature Module, class KB1", NULL };
 static const char *on_asn1_class_kb2[] =   { "Digital Signature Module, class KB2", NULL };
 static const char *on_asn1_class_ka[] =    { "Digital Signature Module, class KA", NULL };

/* Microsoft */
 static const char *on_asn1_ms_cav[] =      { "microsoft CA version", NULL };
 static const char *on_asn1_ms_psh[] =      { "microsoft previous certificate hash", NULL };

#endif

/* ----------------------------------------------------------------------------------------------- */
/*! Константные значения OID библиотеки */
 static struct oid libakrypt_oids[] = {
  /* 1. идентификаторы алгоритмов выработки псевдо-случайных последовательностей,
        значения OID находятся в дереве библиотеки: 1.2.643.2.52.1.1 - генераторы ПСЧ  */
   { random_generator, algorithm, on_lcg, "1.2.643.2.52.1.1.1", NULL,
                                            { ( ak_function_void *) ak_random_context_create_lcg,
                                                 ( ak_function_void *) ak_random_context_destroy,
                                                 ( ak_function_void *) ak_random_context_delete }},

  #if defined(__unix__) || defined(__APPLE__)
   { random_generator, algorithm, on_dev_random, "1.2.643.2.52.1.1.2", NULL,
                                        { ( ak_function_void *) ak_random_context_create_random,
                                                ( ak_function_void *) ak_random_context_destroy,
                                                 ( ak_function_void *) ak_random_context_delete }},

   { random_generator, algorithm, on_dev_urandom, "1.2.643.2.52.1.1.3", NULL,
                                       { ( ak_function_void *) ak_random_context_create_urandom,
                                                ( ak_function_void *) ak_random_context_destroy,
                                                 ( ak_function_void *) ak_random_context_delete }},
  #endif
  #ifdef _WIN32
   { random_generator, algorithm, on_winrtl, "1.2.643.2.52.1.1.4", NULL,
                                        { ( ak_function_void *) ak_random_context_create_winrtl,
                                                ( ak_function_void *) ak_random_context_destroy,
                                                 ( ak_function_void *) ak_random_context_delete }},
  #endif
  #ifdef LIBAKRYPT_CRYPTO_FUNCTIONS
   { random_generator, algorithm, on_hashrnd, "1.2.643.2.52.1.1.5", NULL,
                                       { ( ak_function_void *) ak_random_context_create_hashrnd,
                                                ( ak_function_void *) ak_random_context_destroy,
                                                 ( ak_function_void *) ak_random_context_delete }},

  /* 2. идентификаторы алгоритмов бесключевого хеширования,
        значения OID взяты из перечней КриптоПро и ТК26 (http://tk26.ru/methods/OID_TK_26/index.php)
        в дереве библиотеки: 1.2.643.2.52.1.2 - функции бесключевого хеширования */
   { hash_function, algorithm, on_streebog256, "1.2.643.7.1.1.2.2", NULL,
                                     { ( ak_function_void *) ak_hash_context_create_streebog256,
                                                  ( ak_function_void *) ak_hash_context_destroy,
                                                   ( ak_function_void *) ak_hash_context_delete }},

   { hash_function, algorithm, on_streebog512, "1.2.643.7.1.1.2.3", NULL,
                                     { ( ak_function_void *) ak_hash_context_create_streebog512,
                                                  ( ak_function_void *) ak_hash_context_destroy,
                                                   ( ak_function_void *) ak_hash_context_delete }},

  /* 3. идентификаторы параметров алгоритма бесключевого хеширования ГОСТ Р 34.11-94.
        значения OID взяты из перечней КриптоПро

        в текущей версии библиотеки данные идентификаторы отсутствуют */

  /* 4. идентификаторы алгоритмов HMAC согласно Р 50.1.113-2016
        в дереве библиотеки: 1.2.643.2.52.1.4 - функции ключевого хеширования (имитозащиты) */
   { hmac_function, algorithm, on_hmac_streebog256, "1.2.643.7.1.1.4.1", NULL,
                                     { ( ak_function_void *) ak_hmac_context_create_streebog256,
                                                  ( ak_function_void *) ak_hmac_context_destroy,
                                                   ( ak_function_void *) ak_hmac_context_delete }},

   { hmac_function, algorithm, on_hmac_streebog512, "1.2.643.7.1.1.4.2", NULL,
                                      { ( ak_function_void *)ak_hmac_context_create_streebog512,
                                                  ( ak_function_void *) ak_hmac_context_destroy,
                                                   ( ak_function_void *) ak_hmac_context_delete }},

  /* 6. идентификаторы алгоритмов блочного шифрования
        в дереве библиотеки: 1.2.643.2.52.1.6 - алгоритмы блочного шифрования
        в дереве библиотеки: 1.2.643.2.52.1.7 - параметры алгоритмов блочного шифрования */

   { block_cipher, algorithm, on_magma, "1.2.643.7.1.1.5.1", NULL,
                                          { ( ak_function_void *) ak_bckey_context_create_magma,
                                                 ( ak_function_void *) ak_bckey_context_destroy,
                                                  ( ak_function_void *) ak_bckey_context_delete }},

   { block_cipher, algorithm, on_kuznechik, "1.2.643.7.1.1.5.2", NULL,
                                      { ( ak_function_void *) ak_bckey_context_create_kuznechik,
                                                 ( ak_function_void *) ak_bckey_context_destroy,
                                                  ( ak_function_void *) ak_bckey_context_delete }},

  /* 11. алгоритмы выработки и проверки электронной подписи */
   { sign_function, algorithm, on_sign256, "1.2.643.7.1.1.3.2", NULL,
                                  { ( ak_function_void *) ak_signkey_context_create_streebog256,
                                               ( ak_function_void *) ak_signkey_context_destroy,
                                                ( ak_function_void *) ak_signkey_context_delete }},
   { sign_function, algorithm, on_sign512, "1.2.643.7.1.1.3.3", NULL,
                                  { ( ak_function_void *) ak_signkey_context_create_streebog512,
                                               ( ak_function_void *) ak_signkey_context_destroy,
                                                ( ak_function_void *) ak_signkey_context_delete }},
   { verify_function, algorithm, on_verify256, "1.2.643.7.1.1.1.1", NULL,
                                            { ( ak_function_void *) ak_verifykey_context_create,
                                             ( ak_function_void *) ak_verifykey_context_destroy,
                                              ( ak_function_void *) ak_verifykey_context_delete }},
   { verify_function, algorithm, on_verify512, "1.2.643.7.1.1.1.2", NULL,
                                            { ( ak_function_void *) ak_verifykey_context_create,
                                             ( ak_function_void *) ak_verifykey_context_destroy,
                                              ( ak_function_void *) ak_verifykey_context_delete }},
  #endif

  /* 12. идентификаторы параметров эллиптических кривых, в частности, из Р 50.1.114-2016
         в дереве библиотеки: 1.2.643.2.52.1.12 - параметры эллиптических кривых в форме Вейерштрасса
         в дереве библиотеки: 1.2.643.2.52.1.12.1 - параметры 256 битных кривых
         в дереве библиотеки: 1.2.643.2.52.1.12.2 - параметры 512 битных кривых */
   { identifier, wcurve_params, on_w256_pst, "1.2.643.2.2.35.0",
                      (ak_pointer) &id_tc26_gost_3410_2012_256_paramSetTest, { NULL, NULL, NULL }},
   { identifier, wcurve_params, on_w256_psa, "1.2.643.7.1.2.1.1.1",
                         (ak_pointer) &id_tc26_gost_3410_2012_256_paramSetA, { NULL, NULL, NULL }},
  /* кривая A из 4357 три раза */
   { identifier, wcurve_params, on_w256_psb, "1.2.643.7.1.2.1.1.2",
                          (ak_pointer) &id_rfc4357_gost_3410_2001_paramSetA, { NULL, NULL, NULL }},
   { identifier, wcurve_params, on_w256_ps4357a, "1.2.643.2.2.35.1",
                          (ak_pointer) &id_rfc4357_gost_3410_2001_paramSetA, { NULL, NULL, NULL }},
   { identifier, wcurve_params, on_w256_ps4357d, "1.2.643.2.2.36.0",
                          (ak_pointer) &id_rfc4357_gost_3410_2001_paramSetA, { NULL, NULL, NULL }},
  /* кривая В из 4357 два раза */
   { identifier, wcurve_params, on_w256_psc, "1.2.643.7.1.2.1.1.3",
                          (ak_pointer) &id_rfc4357_gost_3410_2001_paramSetB, { NULL, NULL, NULL }},
   { identifier, wcurve_params, on_w256_ps4357b, "1.2.643.2.2.35.2",
                          (ak_pointer) &id_rfc4357_gost_3410_2001_paramSetB, { NULL, NULL, NULL }},
  /* кривая С из 4357 два раза */
   { identifier, wcurve_params, on_w256_psd, "1.2.643.7.1.2.1.1.4",
                          (ak_pointer) &id_rfc4357_gost_3410_2001_paramSetC, { NULL, NULL, NULL }},
   { identifier, wcurve_params, on_w256_ps4357c, "1.2.643.2.2.35.3",
                          (ak_pointer) &id_rfc4357_gost_3410_2001_paramSetC, { NULL, NULL, NULL }},

  /* теперь кривые длиной 512 бит */
   { identifier, wcurve_params, on_w512_pst, "1.2.643.7.1.2.1.2.0",
                      (ak_pointer) &id_tc26_gost_3410_2012_512_paramSetTest, { NULL, NULL, NULL }},
   { identifier, wcurve_params, on_w512_psa, "1.2.643.7.1.2.1.2.1",
                         (ak_pointer) &id_tc26_gost_3410_2012_512_paramSetA, { NULL, NULL, NULL }},
   { identifier, wcurve_params, on_w512_psb, "1.2.643.7.1.2.1.2.2",
                         (ak_pointer) &id_tc26_gost_3410_2012_512_paramSetB, { NULL, NULL, NULL }},
   { identifier, wcurve_params, on_w512_psc, "1.2.643.7.1.2.1.2.3",
                         (ak_pointer) &id_tc26_gost_3410_2012_512_paramSetC, { NULL, NULL, NULL }},

   { identifier, wcurve_params, on_w256_axel, "1.2.643.2.52.1.12.1.1",
                  (ak_pointer) &id_libakrypt_gost_3410_2012_256_paramSet_N0, { NULL, NULL, NULL }},


  /* идентификаторы объектов, используемых для создания сертификатов открытых ключей
     подробный перечень идентификаторов может быть найден по следующему адресу
     http://www.2410000.ru/p_45_spravochnik_oid_oid__najti_oid_oid_perechen_oid_oid_obektnyj_identifikator_oid_oid_object_identifier.html */

  #ifdef LIBAKRYPT_CRYPTO_FUNCTIONS
   { identifier, parameter, on_asn1_akcont, "1.2.643.2.52.1.127.1.1", NULL, { NULL, NULL, NULL }},
   { identifier, parameter, on_asn1_pbkdf2key, "1.2.643.2.52.1.127.2.1",
                                                                      NULL, { NULL, NULL, NULL }},
   { identifier, parameter, on_asn1_sdhkey, "1.2.643.2.52.1.127.2.2", NULL, { NULL, NULL, NULL }},
   { identifier, parameter, on_asn1_extkey, "1.2.643.2.52.1.127.2.3", NULL, { NULL, NULL, NULL }},

  /* здесь можно добавить указатели на функции создания asn.1 и создания (установки параметров) ключа */
   { identifier, parameter, on_asn1_symkmd, "1.2.643.2.52.1.127.3.1",
                                         (ak_pointer) symmetric_key_content, { NULL, NULL, NULL }},
   { identifier, parameter, on_asn1_skmd, "1.2.643.2.52.1.127.3.2",
                                            (ak_pointer) secret_key_content, { NULL, NULL, NULL }},
   { identifier, parameter, on_asn1_pkmd, "1.2.643.2.52.1.127.3.3",
                                            (ak_pointer) public_key_content, { NULL, NULL, NULL }},
   { identifier, parameter, on_asn1_ecmd, "1.2.643.2.52.1.127.3.4",
                                             (ak_pointer) encrypted_content, { NULL, NULL, NULL }},
   { identifier, parameter, on_asn1_pcmd, "1.2.643.2.52.1.127.3.5",
                                                 (ak_pointer) plain_content, { NULL, NULL, NULL }},

 /* добавляем аттрибуты типов (X.500) и расширенные аттрибуты */
   { identifier, descriptor, on_asn1_ogrn,   "1.2.643.100.1", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_snils,  "1.2.643.100.3", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_ogrnip, "1.2.643.100.5", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_owners_module,  "1.2.643.100.111", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_issuers_module, "1.2.643.100.112", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_inn,   "1.2.643.3.131.1.1", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_email, "1.2.840.113549.1.9.1", NULL, { NULL, NULL, NULL }},

   { identifier, descriptor, on_asn1_cn, "2.5.4.3", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_s, "2.5.4.4", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_sn, "2.5.4.5", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_c, "2.5.4.6", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_l, "2.5.4.7", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_st, "2.5.4.8", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_sa, "2.5.4.9", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_o, "2.5.4.10", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_ou, "2.5.4.11", NULL, { NULL, NULL, NULL }},

   { identifier, descriptor, on_asn1_ski, "2.5.29.14", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_ku, "2.5.29.15", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_bc, "2.5.29.19", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_cp, "2.5.29.32", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_wcp, "2.5.29.32.0", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_aki, "2.5.29.35", NULL, { NULL, NULL, NULL }},

 /* это добро из Приказа ФСБ N 795 */
   { identifier, descriptor, on_asn1_class_kc1, "1.2.643.100.113.1", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_class_kc2, "1.2.643.100.113.2", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_class_kc3, "1.2.643.100.113.3", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_class_kb1, "1.2.643.100.113.4", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_class_kb2, "1.2.643.100.113.5", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_class_ka, "1.2.643.100.113.6", NULL, { NULL, NULL, NULL }},

  /* вот что приходится разбирать в сертификатах от КриптоПро
     Microsoft OID...................................1.3.6.1.4.1.311  */

   { identifier, descriptor, on_asn1_ms_cav, "1.3.6.1.4.1.311.21.1", NULL, { NULL, NULL, NULL }},
   { identifier, descriptor, on_asn1_ms_psh, "1.3.6.1.4.1.311.21.2", NULL, { NULL, NULL, NULL }},
  #endif

 /* завершающая константа, должна всегда принимать неопределенные и нулевые значения */
  { undefined_engine, undefined_mode, NULL, NULL, NULL, { NULL, NULL, NULL }}

 /* при добавлении нового типа (engine)
    не забыть также добавить его обработку в функцию ak_context_node_get_context_oid() */
};

/* ----------------------------------------------------------------------------------------------- */
 static const char *libakrypt_engine_names[] = {
    "identifier",
    "block cipher",
    "stream cipher",
    "hybrid cipher",
    "hash function",
    "hmac function",
    "cmac function",
    "mgm function",
    "mac function",
    "sign function",
    "verify function",
    "random generator",
    "oid engine",
    "undefined engine",
};

/* ----------------------------------------------------------------------------------------------- */
 static const char *libakrypt_mode_names[] = {
    "algorithm",
    "parameter",
    "wcurve params",
    "ecurve params",
    "kbox params",
    "ecb",
    "counter",
    "counter_gost",
    "ofb",
    "cbc",
    "cfb",
    "xts",
    "xtsmac",
    "xcrypt",
    "a8",
    "descriptor",
    "undefined mode"
};

/* ----------------------------------------------------------------------------------------------- */
/*                     реализация функций доступа к глобальному списку OID                         */
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_libakrypt_oids_count( void )
{
 return ( sizeof( libakrypt_oids )/( sizeof( struct oid )) - 1 );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param engine тип криптографического механизма.
    @return Функция возвращает указатель на константную строку.                                    */
/* ----------------------------------------------------------------------------------------------- */
 const char *ak_libakrypt_get_engine_name( const oid_engines_t engine )
{
  if( engine > undefined_engine ) {
    ak_error_message_fmt( ak_error_oid_engine, __func__, "incorrect value of engine: %d", engine );
    return ak_null_string;
  }
 return libakrypt_engine_names[engine];
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param mode режим криптографического механизма.
    @return Функция возвращает указатель на константную строку.                                    */
/* ----------------------------------------------------------------------------------------------- */
 const char *ak_libakrypt_get_mode_name( const oid_modes_t mode )
{
  if( mode > undefined_mode ) {
    ak_error_message_fmt( ak_error_oid_mode, __func__, "incorrect value of engine mode: %d", mode );
    return ak_null_string;
  }
 return libakrypt_mode_names[mode];
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param index Индекс статической структуры oid.
    @param info указатель на контекст, куда будет помещена информация о криптографическом механизме;
    перед вызовом функции, контекст `oid` должен быть размещен в статической или динамической памяти.

    @return Функция возвращает \ref ak_error_ok (ноль) в случае успеха. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 dll_export int ak_libakrypt_get_oid_by_index( const size_t index, ak_oid_info info )
{
 /* проверяем, что мы нужном диапазоне */
  if( index >= ak_libakrypt_oids_count())
    return ak_error_message( ak_error_wrong_index, __func__, "incorrect index value" );
  if( info == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to oid_info context" );
 /* в случае успеха, возвращаем запрашиваемую информацию */
  info->engine = libakrypt_oids[index].engine;
  info->mode = libakrypt_oids[index].mode;
  info->id =  libakrypt_oids[index].id;
  info->names = libakrypt_oids[index].names;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param description Строка, содержащая имя или идентификатор криптографического алгоритма.
    @param info указатель на контекст, куда будет помещена информация о криптографическом механизме;
    перед вызовом функции, контекст `oid` должен быть размещен в статической или динамической памяти.

    @return Функция возвращает \ref ak_error_ok (ноль) в случае успеха. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 dll_export int ak_libakrypt_get_oid( const char *description , ak_oid_info info )
{
  ak_oid oid = NULL;

 /* проверяем область допустимых значений */
  if( description == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                   "using null pointer to string with name/identifer of cryptographic mechanism" );
  if( info == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                        "using null pointer to oid_info context" );
  if(( oid = ak_oid_context_find_by_ni( description )) == NULL )
    return ak_error_message( ak_error_wrong_oid, __func__,
                               "incorrect string with name/identifer of cryptographic mechanism" );
 /* в случае успеха, возвращаем запрашиваемую информацию */
  info->engine = oid->engine;
  info->mode = oid->mode;
  info->id =  oid->id;
  info->names = oid->names;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                          поиск OID - функции внутреннего интерфейса                             */
/* ----------------------------------------------------------------------------------------------- */
/*! @param name строка, содержащая символьное (человекочитаемое) имя криптографического механизма
    или параметра.
    @return Функция возвращает указатель на область памяти, в которой находится структура
    с найденным идентификатором. В случае ошибки, возвращается NULL и устанавливается код ошибки.  */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_context_find_by_name( const char *name )
{
  size_t idx = 0;

 /* надо ли стартовать */
  if( name == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid name" );
    return NULL;
  }
 /* перебор по всем возможным значениям */
  do{
     const char *str = NULL;
     size_t len = 0, jdx = 0;
     while(( str = libakrypt_oids[idx].names[jdx] ) != NULL ) {
        len = strlen( str );
        if(( strlen( name ) == len ) && ak_ptr_is_equal( name, str, len ))
          return  &libakrypt_oids[idx];
        jdx++;
     }
  } while( ++idx < ak_libakrypt_oids_count( ));

  ak_error_set_value( ak_error_oid_id );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param id строка, содержащая символьную запись идентификатора - последовательность чисел,
    разделенных точками.
    @return Функция возвращает указатель на область памяти, в которой находится структура
    с найденным идентификатором. В случае ошибки, возвращается NULL.                               */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_context_find_by_id( const char *id )
{
  size_t len = 0, idx = 0;
  if( id == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid identifier" );
    return NULL;
  }

  do{
     if(( strlen( id ) == ( len = strlen( libakrypt_oids[idx].id ))) &&
                 ak_ptr_is_equal( id, libakrypt_oids[idx].id, len ))
       return  &libakrypt_oids[idx];

  } while( ++idx < ak_libakrypt_oids_count( ));

  ak_error_set_value( ak_error_oid_id );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ni строка, содержащая символьную запись имени или идентификатора - последовательности
    чисел, разделенных точками.
    @return Функция возвращает указатель на область памяти, в которой находится структура
    с найденным идентификатором. В случае ошибки, возвращается NULL.                               */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_context_find_by_ni( const char *ni )
{
  size_t idx = 0;
  if( ni == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                                  "using null pointer to oid name or identifier" );
    return NULL;
  }

 /* основной перебор */
  do{
     const char *str = NULL;
     size_t jdx = 0, len = strlen( libakrypt_oids[idx].id );

    /* проверка идентификатора */
     if(( strlen( ni ) == len) && ak_ptr_is_equal( ni, libakrypt_oids[idx].id, len ))
       return &libakrypt_oids[idx];

    /* проверка имени */
     while(( str = libakrypt_oids[idx].names[jdx] ) != NULL ) {
        len = strlen( str );
        if(( strlen( ni ) == len ) && ak_ptr_is_equal( ni, str, len ))
          return  &libakrypt_oids[idx];
        jdx++;
     }
  } while( ++idx < ak_libakrypt_oids_count( ));

  ak_error_set_value( ak_error_oid_id );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param ptr указатель а область памяти, по которой ищется oid
    @return Функция возвращает указатель на область памяти, в которой находится структура
    с найденным идентификатором. В случае ошибки, возвращается NULL.                               */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_context_find_by_data( ak_const_pointer ptr )
{
  size_t idx = 0;

 /* надо ли стартовать */
  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid name" );
    return NULL;
  }

 /* перебор по всем возможным значениям */
  do{
     if( libakrypt_oids[idx].data == ptr ) return  &libakrypt_oids[idx];
  } while( ++idx < ak_libakrypt_oids_count( ));

  ak_error_set_value( ak_error_oid_id );
 return NULL;
}


/* ----------------------------------------------------------------------------------------------- */
/*! @param engine тип криптографическиого механизма.

    @return В случае успешного поиска функция возвращает указатель на  область памяти, в которой
    находится структура с найденным идентификатором. В случае ошибки, возвращается NULL.           */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_context_find_by_engine( const oid_engines_t engine )
{
  size_t idx = 0;
  do{
     if( libakrypt_oids[idx].engine == engine ) return (const ak_oid) &libakrypt_oids[idx];
  } while( ++idx < ak_libakrypt_oids_count( ));
  ak_error_message( ak_error_oid_name, __func__, "searching oid with wrong engine" );

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param startoid предыдущий найденный oid.
    @param engine тип криптографическиого механизма.

    @return В случае успешного поиска функция возвращает указатель на  область памяти, в которой
    находится структура с найденным идентификатором. В случае ошибки, возвращается NULL.           */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid ak_oid_context_findnext_by_engine( const ak_oid startoid, const oid_engines_t engine )
{
 ak_oid oid = ( ak_oid )startoid;

 if( oid == NULL) {
   ak_error_message( ak_error_null_pointer, __func__, "using null pointer to oid" );
   return NULL;
 }

 /* сдвигаемся по массиву OID вперед */
  while( (++oid)->engine != undefined_engine ) {
    if( oid->engine == engine ) return (const ak_oid) oid;
  }

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param oid Тестируемый на корректность адрес
    @return Функция возвращает истину, если заданный адрес `oid` дествительности содержится
    среди предопределенных oid библиотеки.                                                         */
/* ----------------------------------------------------------------------------------------------- */
 bool_t ak_oid_context_check( const ak_oid oid )
{
  size_t i;
  bool_t result = ak_false;

  for( i = 0; i < ak_libakrypt_oids_count(); i++ )
     if( (const ak_oid) &libakrypt_oids[i] == oid ) result = ak_true;

 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*!  \example test-oid01.c                                                                         */
/*!  \example test-oid02.c                                                                         */
/*!  \example test-oid03.c                                                                         */
/*!  \example example-oid.c                                                                        */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                       ak_oid.c  */
/* ----------------------------------------------------------------------------------------------- */
