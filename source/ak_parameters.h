/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2010-2016 by Axel Kenzo, axelkenzo@mail.ru                                      */
/*   All rights reserved.                                                                          */
/*                                                                                                 */
/*   Redistribution and use in source and binary forms, with or without modification, are          */
/*   permitted provided that the following conditions are met:                                     */
/*                                                                                                 */
/*   1. Redistributions of source code must retain the above copyright notice, this list of        */
/*      conditions and the following disclaimer.                                                   */
/*   2. Redistributions in binary form must reproduce the above copyright notice, this list of     */
/*      conditions and the following disclaimer in the documentation and/or other materials        */
/*      provided with the distribution.                                                            */
/*   3. Neither the name of the copyright holder nor the names of its contributors may be used     */
/*      to endorse or promote products derived from this software without specific prior written   */
/*      permission.                                                                                */
/*                                                                                                 */
/*   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS   */
/*   OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF               */
/*   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL        */
/*   THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, */
/*   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE */
/*   GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED    */
/*   AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     */
/*   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED  */
/*   OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/*                                                                                                 */
/*   ak_parameters.h                                                                               */
/* ----------------------------------------------------------------------------------------------- */
#ifndef    __AK_PARAMETERS_H__
#define    __AK_PARAMETERS_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_hash.h>
 #include <ak_curves.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тестовые значения перестановок для алгоритма шифрования ГОСТ 28147-89 (Магма)           */
 static const kbox cipher_box = {
                { 4, 2, 15, 5, 9, 1, 0, 8, 14, 3, 11, 12, 13, 7, 10, 6 },
                { 12, 9, 15, 14, 8, 1, 3, 10, 2, 7, 4, 13, 6, 0, 11, 5 },
                { 13, 8, 14, 12, 7, 3, 9, 10, 1, 5, 2, 4, 6, 15, 0, 11 },
                { 14, 9, 11, 2, 5, 15, 7, 1, 0, 13, 12, 6, 10, 4, 3, 8 },
                { 3, 14, 5, 9, 6, 8, 0, 13, 10, 11, 7, 12, 2, 1, 15, 4 },
                { 8, 15, 6, 11, 1, 9, 12, 5, 13, 3, 7, 10, 0, 14, 2, 4 },
                { 9, 11, 12, 0, 3, 6, 7, 5, 4, 8, 14, 15, 1, 10, 2, 13 },
                { 12, 6, 5, 2, 11, 0, 9, 13, 3, 14, 7, 10, 15, 4, 1, 8 }
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Фиксированные значения перестановок для алгоритма шифрования ГОСТ 28147-89 (Магма)
    Значения таблиц взяты из ГОСТ Р 34.12-2015                                                     */
 static const kbox cipher_box_magma = {
                { 12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1 },
                { 6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15 },
                { 11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0 },
                { 12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11 },
                { 7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12 },
                { 5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0 },
                { 8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7 },
                { 1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2 }
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Фиксированные значения перестановок для алгоритма шифрования ГОСТ 28147-89 (Магма)
    Значения перестановок взяты из RFC 4357                                                        */
 static const kbox cipher_box_CSPA = {
               { 9, 6, 3, 2, 8, 11, 1, 7, 10, 4, 14, 15, 12, 0, 13, 5 },
               { 3, 7, 14, 9, 8, 10, 15, 0, 5, 2, 6, 12, 11, 4, 13, 1 },
               { 14, 4, 6, 2, 11, 3, 13, 8, 12, 15, 5, 10, 0, 7, 1, 9 },
               { 14, 7, 10, 12, 13, 1, 3, 9, 0, 2, 11, 4, 15, 8, 5, 6 },
               { 11, 5, 1, 9, 8, 13, 15, 0, 14, 4, 2, 3, 12, 7, 10, 6 },
               { 3, 10, 13, 12, 1, 2, 0, 11, 7, 5, 9, 4, 8, 15, 14, 6 },
               { 1, 13, 2, 9, 7, 10, 6, 0, 8, 12, 4, 5, 15, 3, 11, 14 },
               { 11, 10, 15, 5, 0, 12, 14, 8, 6, 2, 3, 9, 1, 7, 13, 4 }
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Перестановки со значениями по-умолчанию для алгоритма бесключевого хеширования.
    Определены ГОСТР Р 34.11-94, приложение А.                                                     */
 static const kbox hash_box = {
                { 4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3 },
                { 14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9 },
                { 5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11 },
                { 7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3 },
                { 6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2 },
                { 4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14 },
                { 13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12 },
                { 1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12 }
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Перестановки для алгоритма хеширования ГОСТ Р 34.11-94.
    Набор параметров А компании КриптоПро                                                          */
 static const kbox hash_box_CSPA = {
                { 10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15 },
                { 5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8 },
                { 7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13 },
                { 4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3 },
                { 7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5 },
                { 7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3 },
                { 13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11 },
                { 1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12 }
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Перестановки для алгоритма хеширования ГОСТ Р 34.11-94.
    Набор параметров средства ВербаО                                                               */
 static const kbox hash_box_VerbaO = {
                { 3, 6, 7, 8, 2, 5, 12, 14, 9, 13, 0, 10, 1, 11, 4, 15 },
                { 1, 13, 6, 2, 9, 10, 4, 3, 7, 14, 5, 11, 12, 0, 15, 8 },
                { 7, 15, 12, 3, 0, 13, 10, 5, 14, 9, 11, 2, 4, 1, 6, 8 },
                { 11, 4, 9, 1, 6, 8, 13, 10, 0, 3, 7, 14, 5, 12, 15, 2 },
                { 3, 15, 10, 0, 2, 5, 11, 6, 9, 14, 1, 8, 13, 12, 7, 4 },
                { 13, 9, 4, 11, 7, 12, 8, 3, 10, 2, 1, 15, 5, 6, 0, 14 },
                { 1, 4, 9, 3, 10, 0, 15, 2, 7, 12, 11, 13, 14, 6, 8, 5 },
                { 4, 10, 8, 11, 1, 13, 14, 6, 9, 2, 12, 15, 7, 0, 5, 3 }
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры эллиптической кривой из тестового примера ГОСТ Р 34.10-2012 (Приложение А.1)  */
 static const struct wcurve_paramset wcurve_gost_3410_2012_test256 = {
  ak_mpzn256_size,
  "7",                                                                // a
  "5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E", // b
  "8000000000000000000000000000000000000000000000000000000000000431", // p
  "8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3", // q
  "2",                                                                // px
  "8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8",  // py
  "464584",                                                           // r2
  0xDBF951D5883B2B2FLL,                                               // n
  1                                                                   // d
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры эллиптической кривой из тестового примера ГОСТ Р 34.10-2012 (Приложение А.2)  */
 static const struct wcurve_paramset wcurve_gost_3410_2012_test512 = {
  ak_mpzn512_size,
  "7",                                                                                                                                // a
  "1CFF0806A31116DA29D8CFA54E57EB748BC5F377E49400FDD788B649ECA1AC4361834013B2AD7322480A89CA58E0CF74BC9E540C2ADD6897FAD0A3084F302ADC", // b
  "4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DF1D852741AF4704A0458047E80E4546D35B8336FAC224DD81664BBF528BE6373", // p
  "4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DA82F2D7ECB1DBAC719905C5EECC423F1D86E25EDBE23C595D644AAF187E6E6DF", // q
  "24D19CC64572EE30F396BF6EBBFD7A6C5213B3B3D7057CC825F91093A68CD762FD60611262CD838DC6B60AA7EEE804E28BC849977FAC33B4B530F1B120248A9A", // px
  "2BB312A43BD2CE6E0D020613C857ACDDCFBF061E91E5F2C3F32447C259F39B2C83AB156D77F1496BF7EB3351E1EE4E43DC1A18B91B24640B6DBB92CB1ADD371E", // py
  "1d887dcd9cd19c1001fde9ca99de0852fcd983cfb7c663d9ca0bc8af77c8690a0815b9eb1e7dd300e417d58d200c2aa04b907a71e647ee63001c10bc2d005b65", // r2
  0xd6412ff7c29b8645LL,                                               // n
  1                                                                   // d
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры эллиптической кривой из рекомендаций Р 50.1.114-2016 (paramSetA)              */
 static const struct wcurve_paramset wcurve_tc26_gost_3410_2012_512_paramSetA = {
  ak_mpzn512_size,
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4", //a
  "E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760", //b
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7", // p
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275", /* q */
  "3",                  // px
  "7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4", // py
  "4F0B1",              // r2
  0x58a1f7e6ce0f4c09LL, // n
  1                     // d
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры эллиптической кривой из рекомендаций Р 50.1.114-2016 (paramSetB)              */
 static const struct wcurve_paramset wcurve_tc26_gost_3410_2012_512_paramSetB = {
  ak_mpzn512_size,
  "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C", //a
  "687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116", //b
  "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F", // p
  "800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD", // q
  "2", // px
  "1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD", // py
  "C084", // r2
  0x4e6a171024e6a171, // n
  1                   // d
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры эллиптической кривой из рекомендаций Р 50.1.114-2016 (paramSetC)              */
 static const struct wcurve_paramset wcurve_tc26_gost_3410_2012_512_paramSetC = {
  ak_mpzn512_size,
  "DC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E143064546E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3", // a
  "B4C4EE28CEBC6C2C8AC12952CF37F16AC7EFB6A9F69F4B57FFDA2E4F0DE5ADE038CBC2FFF719D2C18DE0284B8BFEF3B52B8CC7A5F5BF0A3C8D2319A5312557E1", // b
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7", // p
  "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC98CDBA46506AB004C33A9FF5147502CC8EDA9E7A769A12694623CEF47F023ED", // q
  "E2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043AA27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148", // px
  "F5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9BE18E2D33E3021ED2EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40F", // py
  "4F0B1", // r2
  0x58a1f7e6ce0f4c09LL, // n
  4       // d
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры эллиптической кривой выработанные авторами библиотеки (paramSetA)             */
 static const struct wcurve_paramset wcurve_axel_gost_3410_2012_512_paramSetA = {
  ak_mpzn512_size,
  "80007C0D100DE1DA4C082D55B224E1F6995C0200BAE1827110D0CE783E5EBD08AFACCA5A732368521E0BAD88865E21DA43DA42B35757B8038768059BE89E36AD", /* a */
  "7633E0B39500943957990D315BE1F4B2B971527863EB30D9D1A0B52A8489484212502F709F1D067DFC109E06AF608B8DD4F854E4F45DF4309506452C499A102D", /* b */
  "80007C0D100DE1DA4C082D55B224E1F6995C0200BAE1827110D0CE783E5EBD08AFACCA5A732368521E0BAD88865E21DA43DA42B35757B8038768059BE89E36AF", /* p */
  "80007C0D100DE1DA4C082D55B224E1F6995C0200BAE1827110D0CE783E5EBD091D1C41E039FB32B9D6115C0919412876018EF3923B4255F8717DB632094F9B5B", /* q */
  "3",                  /* px */
  "3F1F3A51B164FFC05E7221D67A01B361870727C3DF007D3A9FDB7A1E9230F0781D69806E0CC5E38CB62B18E2D6D4BCF12112F42600D5783AE109F64B0D2845B5", /* py */
  "53590545a052051b87fdda647bb639ca73f78460a43b9f6695e660d3b641c6d7693b56cc4d41c7fb42d778a51b701611a5c29e884d86660d10e955e894409333", /* r2 */
  0x8f69d5c0fd131fb1LL, /* n */
  1                     /* d */
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры эллиптической кривой выработанные авторами библиотеки (paramSetB)             */
 static const struct wcurve_paramset wcurve_axel_gost_3410_2012_512_paramSetB = {
  ak_mpzn512_size,
  "1",                                                                                                                                /* a */
  "11E29E2367B263B37545AC4A9BBE564E8A2E25B49D4E620BF07B308E1189644B740AE15958A44ADDFB4F77DC365FA6F08E9397274C37687953DAA9AD9FE3010F", /* b */
  "80003A690DDAAAA5D14A4B1ABDB0390505E82546010D4B28B1C1B8D08E1E52E275972F60668C92FE74F9748FE7AFF1063BC231D360315F16C639A529D7F699FB", /* p */
  "80003A690DDAAAA5D14A4B1ABDB0390505E82546010D4B28B1C1B8D08E1E52E120A68246EAB995BA91AE106319ACF9DF05ECBB993C4564857A013A16F7452F5B", /* q */
  "1",                                                                                                                                /* px */
  "9614E93557682D0F3AAD2EA29ACC3C4A64AE0E42E62E1BC805BFA45A604C0C64D6BFF63BED45F20C3B3064454D1B031759264F25B49771082B34590A2C7295A",  /* py */
  "233ecd65f77ed4cb3b33126371393446e85db7fb1175066cccaabdbf2d5c9a01cb1d0441cdff6fa581d3ff8245e3db6c96cb2de3b544a51c9ee70e5dee9e2bdb", /* r2 */
  0xe6738ae17d1776cdLL, /* n */
  1                     /* d */
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Параметры эллиптической кривой выработанные авторами библиотеки (paramSetC)             */
 static const struct wcurve_paramset wcurve_axel_gost_3410_2012_512_paramSetC = {
  ak_mpzn512_size,
  "1",                                                                                                                                /* a */
  "6DE882E107CBB79E498632E1CBB2674CBB713B2D846D1F2BA7E74652A82CBF7FE87A16F01E0E1ABC3176556A4401AFC598D157170A4A3D5AAE7394A72021BD77", /* b */
  "80005724AC7962B5358CA46D35B23177FACB84B8608FA6114F7D22890E054BE7176EA863DC4DDEED87A334AAEEA44DE2C54DA6349BCCBA25ABE90B9AEAC16D8F", /* p */
  "80005724AC7962B5358CA46D35B23177FACB84B8608FA6114F7D22890E054BE82808437B578450CA5C762FDFE35A3A0E2A45420ED5DF11450BFCD70C24FEB7E3", /* q */
  "3",                                                                                                                                /* px */
  "74C8DBB01D7CAEA9ED937E5A53209B483E8B09F5CF6427E2732B8C74DD6B39281186576DB6A9124A6C714E6D90601D2A87ACDABF5987A40759E9B392A4B841DA", /* py */
  "49d741dadedc74e33abe3f4e5d2ac7d7f070ed2e4bebd38997d80da77bb33795b648604604ba09afd679b4b943d3936984a51d1692ec995d133ec6c914dcf9f8", /* r2 */
  0xb55c3991c30aee91LL, /* n */
  1                     /* d */
};

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                 ak_parameters.h */
/* ----------------------------------------------------------------------------------------------- */
