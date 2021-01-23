#! /bin/bash
# скрипт для проверки совместимости реализаций openssl и aktool
# в части выработки и проверки сертификатов открытых ключей
#
# ------------------------------------------------------------------------------------------------- #
# 1. Проверяем наличие тестируемых программ
# ------------------------------------------------------------------------------------------------- #
openssl engine gost -c -vvvv
if [[ $? -ne 0 ]]
then echo "openssl not found, test is unavailable"; exit;
fi
./aktool test --crypt
if [[ $? -ne 0 ]]
then echo "aktool not found, test is unavailable"; exit;
fi
#
# ------------------------------------------------------------------------------------------------- #
# 2. Проверяем возможность создания и взаимной проверки запросов на сертификат
# ------------------------------------------------------------------------------------------------- #
# создаем запрос на сертификат
openssl req -newkey gost2012_256 -pkeyopt paramset:A -out openssl256_request.csr -keyout openssl256.key -passout pass:321!azO -subj "/C=RU/ST=Somewhere/L=Lies/O=The Truth/OU=But Where?"
if [[ $? -ne 0 ]]
then echo "openssl can't create of certificate's request"; exit;
fi
#
# и мы пытаемся это прочесть и верифицировать
./aktool k -s openssl256_request.csr
if [[ $? -ne 0 ]]
then echo "aktool can't verify a certificate's request"; exit;
fi
echo "verification of the openssl256_request.csr is Ok";
./aktool a openssl.key
echo "structure of the openssl_key.pem is present";
#
# теперь сами создаем запрос на сертификат и проверяем его с помощью openssl
./aktool k -nt sign256 -o akrypt256.key --password 321!azO --op akrypt256_request.csr --to pem --id "/ctRU/stSomewhere/ltLies/orThe Truth/ou/With Overall Gladness/ememail@somewhere.lies/cnBut Where?"
openssl req -verify -in akrypt256_request.csr -text
if [[ $? -ne 0 ]]
then echo "openssl can't verify an akrypt_request.csr"; exit;
fi
echo "akrypt256_request.csr is verified";
#
echo ""
#
# ------------------------------------------------------------------------------------------------- #
# 3. Проверяем возможность создания и взаимной проверки самоподписанных сертификатов
# ------------------------------------------------------------------------------------------------- #
# создаем самоподписанный сертификат
openssl req -x509 -newkey gost2012_512 -pkeyopt paramset:A -out openssl512_ca.crt -keyout openssl512.key -passout pass:321!azO -subj "/C=RU/ST=Somewhere/L=Lies/O=The Truth/OU=But Where? Part II"
if [[ $? -ne 0 ]]
then echo "openssl can't create of selfsigned certificate"; exit;
fi
# и мы пытаемся это прочесть и верифицировать
./aktool k -s openssl512_ca.crt
if [[ $? -ne 0 ]]
then echo "aktool can't verify a self-signed certificate"; exit;
fi
echo "verification of the openssl512_ca.csr is Ok";




# ------------------------------------------------------------------------------------------------- #
# 5. Очищаем за собой простанство
# ------------------------------------------------------------------------------------------------- #
# rm -f openssl256_request.csr openssl256.key akrypt256_request.csr akrypt256.key openssl512_ca.crt openssl512.key
