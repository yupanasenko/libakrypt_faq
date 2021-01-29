#! /bin/bash
# скрипт для проверки совместимости реализаций openssl и aktool
# в части выработки и проверки сертификатов открытых ключей
#
# указываем расположение утилиты aktool
export AKTOOL=./aktool;
#
# указываем расположение файла конфигурации openssl
export SSLCONF=/etc/ssl/openssl.cnf;
#
# ------------------------------------------------------------------------------------------------- #
echo "1. Проверяем наличие тестируемых программ"; echo;
# ------------------------------------------------------------------------------------------------- #
openssl engine gost -c -vvvv
if [[ $? -ne 0 ]]
then echo "openssl not found, test is unavailable"; exit;
fi
${AKTOOL} test --crypt
if [[ $? -ne 0 ]]
then echo "aktool not found, test is unavailable"; exit;
fi
#
# ------------------------------------------------------------------------------------------------- #
echo; echo "2. Проверяем возможность создания и взаимной проверки запросов на сертификат"; echo;
# ------------------------------------------------------------------------------------------------- #
# создаем запрос на сертификат
openssl req -newkey gost2012_256 -pkeyopt paramset:A -out openssl256_request.csr -keyout openssl256.key -passout pass:321azO -subj "/C=RU/ST=Somewhere/L=Lies/O=The Truth/OU=But Where?/CN=Openssl Team (256)"
if [[ $? -ne 0 ]]
then echo "openssl can't create of certificate's request"; exit;
fi
#
# и мы пытаемся это прочесть и верифицировать
${AKTOOL} k -s openssl256_request.csr
if [[ $? -ne 0 ]]
then echo "aktool can't verify a certificate's request"; exit;
fi
echo "verification of the openssl256_request.csr is Ok";
${AKTOOL} a openssl.key
echo "structure of the openssl_key.pem is present";
#
# теперь сами создаем запрос на сертификат и проверяем его с помощью openssl
${AKTOOL} k -nt sign256 -o akrypt256.key --outpass 321azO --op akrypt256_request.csr --to pem --id "/ctRU/stSomewhere/ltLies/orThe Truth/ou/With Overall Gladness/lnBut Where?/ememail@somewhere.lies/cnAktool Team (256)"
openssl req -verify -in akrypt256_request.csr -text
if [[ $? -ne 0 ]]
then echo "openssl can't verify an akrypt_request.csr"; exit;
fi
echo "akrypt256_request.csr is verified";
#
echo ""
#
# ------------------------------------------------------------------------------------------------- #
echo; echo "3. Проверяем возможность создания и взаимной проверки самоподписанных сертификатов"; echo;
# ------------------------------------------------------------------------------------------------- #
# сперва, создаем самоподписанный сертификат с помощью aktool
${AKTOOL} k -nt sign512 --curve ec512b -o akrypt512.key --outpass 321azO --op akrypt512_ca.crt --to certificate --id "/ctRU/stSomewhere/ltLies/orThe Truth/ou/With Overall Gladness/lnBut Where?/ememail@somewhere.lies/cnAktool Team(512)"
if [[ $? -ne 0 ]]
then echo "aktool can't create of self-signed certificate"; exit;
fi
# проверяем его самостоятельно
echo ""
${AKTOOL} k -s akrypt512_ca.crt
if [[ $? -ne 0 ]]
then echo "aktool can't verify a self-signed certificate"; exit;
fi
# потом проверяем его через openssl
echo ""
openssl verify -CAfile akrypt512_ca.crt akrypt512_ca.crt
if [[ $? -ne 0 ]]
then echo "openssl can't verified a self-signed certificate"; exit;
fi
# создаем самоподписанный сертификат
openssl req -x509 -newkey gost2012_512 -pkeyopt paramset:A -out openssl512_ca.crt -keyout openssl512.key -passout pass:321azO -subj "/C=RU/ST=Somewhere/L=Lies/O=The Truth/OU=But Where? Part II/CN=Openssl Team (512)"
if [[ $? -ne 0 ]]
then echo "openssl can't create of self-signed certificate"; exit;
fi
# и мы пытаемся это прочесть и верифицировать
${AKTOOL} k -s openssl512_ca.crt
if [[ $? -ne 0 ]]
then echo "aktool can't verify a self-signed certificate"; exit;
fi
echo "verification of the openssl512_ca.csr is Ok";
#
# ------------------------------------------------------------------------------------------------- #
echo; echo "4. Проверяем процедуры подписания запросов на сертифкат секретным ключом эмитента"; echo;
# ------------------------------------------------------------------------------------------------- #
#
echo 012345 > openssl512_ca.srl
openssl x509 -req -days 730 -CA openssl512_ca.crt -passin pass:321azO -CAkey openssl512.key -extfile ${SSLCONF} -extensions usr_cert -in openssl256_request.csr -out openssl256_certificate.crt
if [[ $? -ne 0 ]]
then echo "openssl can't create a user certificate"; exit;
fi
openssl verify -CAfile openssl512_ca.crt openssl256_certificate.crt
${AKTOOL} k -v openssl256_certificate.crt --cakey openssl512_ca.crt
if [[ $? -ne 0 ]]
then echo "aktool can't verify an user certificate, please add the value \"keyUsage = keyCertSign\" in ${SSLCONF} file"; exit;
fi
echo ""
openssl x509 -req -days 730 -CA openssl512_ca.crt -passin pass:321azO -CAkey openssl512.key -extfile ${SSLCONF} -extensions usr_cert -in akrypt256_request.csr -out akrypt256_certificate.crt
if [[ $? -ne 0 ]]
then echo "openssl can't create a user certificate"; exit;
fi
openssl verify -CAfile openssl512_ca.crt akrypt256_certificate.crt
${AKTOOL} k -v akrypt256_certificate.crt --cakey openssl512_ca.crt
if [[ $? -ne 0 ]]
then echo "aktool can't verify an user certificate, please add the value \"keyUsage = keyCertSign\" in ${SSLCONF} file"; exit;
fi
echo ""


##
## теперь тоже самое, но для запроса созданного aktool
#openssl x509 -req -days 730 -CA openssl512_ca.crt -passin pass:321azO -CAkey openssl512.key -extfile ${SSLCONF} -extensions usr_cert -in akrypt256_request.csr -out akrypt256_certificate.crt
#if [[ $? -ne 0 ]]
#then echo "openssl can't create a user certificate"; exit;
#fi
#openssl verify -CAfile openssl512_ca.crt akrypt256_certificate.crt
#${AKTOOL} k -s akrypt256_certificate.crt
##
## реализуем обратную процедуру - теперь aktool вырабатывает сертификаты


# ------------------------------------------------------------------------------------------------- #
echo; echo "5. Очищаем за собой пространство"; echo;
# ------------------------------------------------------------------------------------------------- #
#rm -f openssl256_request.csr openssl256.key
#rm -f akrypt256_request.csr akrypt256.key
#rm -f openssl512_ca.crt openssl512.key
#rm -f akrypt512.key akrypt512_ca.crt
#rm -f openssl256_certificate.crt akrypt256_certificate.crt
