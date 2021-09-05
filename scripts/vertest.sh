##########################################################################
#! /bin/bash
#
# скрипт проверяет глубину вложенности проверки сертификатов
#
##########################################################################
# 1. В начале создаем самоподписанный сертификат УЦ
#
aktool k -nt sign512 --curve ec512c -o secret-ca.key --op public-ca.crt --ca --to certificate --id "Aktool CA" --outpass 321azO --days 1
if [[ $? -ne 0 ]]
then echo "aktool не может создать корневой сертификат"; exit;
fi
aktool k -v public-ca.crt
#
#

##########################################################################
# 2. Помещаем созданный сертификат во временный репозиторий сертификатов
mkdir .ca
aktool k --repo-add public-ca.crt --repo .ca
if [[ $? -ne 0 ]]
then echo "aktool не может добавить корневой сертификат в хранилище"; exit;
fi
echo "Проверяем репозиторий"
aktool k --repo-check --repo .ca # проверяем, что в хранидище находятся валидные сертификаты
#
#

##########################################################################
# 3. Вырабатываем сертификат УЦ первого уровня 
aktool k -nt sign512 --curve ec512b -o secret-l1.key --op public-l1.csr --id "Aktool Level I" --to pem --outpass 321azO
if [[ $? -ne 0 ]]
then echo "aktool не может создать запрос на сертификат"; exit;
fi
aktool k -v public-l1.csr
echo;
#
aktool k -c public-l1.csr --op public-l1.crt --to pem --ca-key secret-ca.key --inpass 321azO --ca-cert public-ca.crt --days 1 --ca-ext true --key-cert-sign
if [[ $? -ne 0 ]]
then echo "aktool не может создать сертификат !!!"; exit;
fi
aktool k -v public-l1.crt --repo .ca
if [[ $? -ne 0 ]]
then echo "aktool не может верифицировать сертификат удостоверяющего центра первого уровня"; exit;
fi
aktool k --repo-add public-l1.crt --repo .ca
if [[ $? -ne 0 ]]
then echo "aktool не может добавить сертификат удостоверяющего центра первого уровня в хранилище"; exit;
fi
#
#
##########################################################################
# 4. Вырабатываем сертификат УЦ второго уровня 
aktool k -nt sign512 --curve ec512b -o secret-l2.key --op public-l2.csr --id "Aktool Level II" --to pem --outpass 321azO
if [[ $? -ne 0 ]]
then echo "aktool не может создать запрос на сертификат"; exit;
fi
aktool k -v public-l2.csr
echo;
#
aktool k -c public-l2.csr --op public-l2.crt --to pem --ca-key secret-l1.key --inpass 321azO --ca-cert public-l1.crt --days 1 --ca --repo .ca
if [[ $? -ne 0 ]]
then echo "aktool не может создать сертификат !!!"; exit;
fi
aktool k -v public-l2.crt --repo .ca 
if [[ $? -ne 0 ]]
then echo "aktool не может верифицировать сертификат удостоверяющего центра второго уровня"; exit;
fi
aktool k --repo-add public-l2.crt --repo .ca
if [[ $? -ne 0 ]]
then echo "aktool не может добавить сертификат удостоверяющего центра второго уровня в хранилище"; exit;
fi

##########################################################################
# 5. Вырабатываем сертификат УЦ третьего уровня 
aktool k -nt sign512 --curve ec512b -o secret-l3.key --op public-l3.csr --id "Aktool Level III" --to pem --outpass 321azO
if [[ $? -ne 0 ]]
then echo "aktool не может создать запрос на сертификат"; exit;
fi
aktool k -v public-l3.csr
echo;
#
aktool k -c public-l3.csr --op public-l3.crt --to pem --ca-key secret-l2.key --inpass 321azO --ca-cert public-l2.crt --days 1 --ca --repo .ca
if [[ $? -ne 0 ]]
then echo "aktool не может создать сертификат (уровень три)"; exit;
fi
aktool k -v public-l3.crt --repo .ca 
if [[ $? -ne 0 ]]
then echo "aktool не может верифицировать сертификат удостоверяющего центра третьего уровня"; exit;
fi
aktool k --repo-add public-l3.crt --repo .ca
if [[ $? -ne 0 ]]
then echo "aktool не может добавить сертификат удостоверяющего центра третьего уровня в хранилище"; exit;
fi

##########################################################################
# 6. Вырабатываем сертификат УЦ четвертого уровня 
aktool k -nt sign512 --curve ec512b -o secret-l4.key --op public-l4.csr --id "Aktool Level IV" --to pem --outpass 321azO
if [[ $? -ne 0 ]]
then echo "aktool не может создать запрос на сертификат"; exit;
fi
aktool k -v public-l4.csr
echo;
#
aktool k -c public-l4.csr --op public-l4.crt --to pem --ca-key secret-l3.key --inpass 321azO --ca-cert public-l3.crt --days 1 --ca --repo .ca
if [[ $? -ne 0 ]]
then echo "aktool не может создать сертификат (уровень 4)"; exit;
fi
aktool k -v public-l4.crt --repo .ca 
if [[ $? -ne 0 ]]
then echo "aktool не может верифицировать сертификат удостоверяющего центра четвертого уровня"; exit;
fi
aktool k --repo-add public-l4.crt --repo .ca
if [[ $? -ne 0 ]]
then echo "aktool не может добавить сертификат удостоверяющего центра четвертого уровня в хранилище"; exit;
fi

##########################################################################
# 7. Завершаем собственный эксерсиз и вырабатываем сертификат пользователя 
aktool k -nt sign256 -o secret-user.key --op public-user.csr --id "/cn=Aktool User Certificate/em=user@mail.mail" --to pem --outpass 321azO
if [[ $? -ne 0 ]]
then echo "aktool не может создать запрос на сертификат"; exit;
fi
aktool k -v public-user.csr
echo;
#
aktool k -c public-user.csr --op public-user.crt --to pem --ca-key secret-l4.key --inpass 321azO --ca-cert public-l4.crt --days 1 --repo .ca
if [[ $? -ne 0 ]]
then echo "aktool не может создать сертификат"; exit;
fi
aktool k -v public-user.crt --repo .ca --verbose
if [[ $? -ne 0 ]]
then echo "aktool не может верифицировать сертификат пользователя"; exit;
fi
echo;

##########################################################################
# 8. Упражнение с сертфикатами тестового УЦ от КриптоПро
wget http://testca2012.cryptopro.ru/cert/rootca.cer
wget http://testca2012.cryptopro.ru/cert/subca.cer
aktool k --repo-add rootca.cer subca.cer --repo .ca
if [[ $? -ne 0 ]]
then echo "aktool не может добавить в хранилище сертификаты тестового УЦ от КриптоПро"; exit;
fi

#
#
##########################################################################
# на-последок, показываем, что натворили и удаляем созданные файлы
aktool k --repo-ls --repo .ca
rm -f secret-ca.key public-ca.crt
rm -f secret-l1.key public-l1.csr public-l1.crt
rm -f secret-l2.key public-l2.csr public-l2.crt
rm -f secret-l3.key public-l3.csr public-l3.crt
rm -f secret-l4.key public-l4.csr public-l4.crt
rm -f secret-user.key public-user.csr public-user.crt
rm .ca/*.cer
rm rootca.cer subca.cer
rmdir .ca

