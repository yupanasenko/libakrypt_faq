#! /bin/bash
#
# скрипт проверяет глубину вложенности проверки сертификатов
# вначале создаем самоподписанный сертификат УЦ
#
aktool k -nt sign512 --curve ec512c -o secret-ca.key --op public-ca.crt --to certificate --id "Aktool CA" --outpass 321azO --days 1
if [[ $? -ne 0 ]]
then echo "aktool не может создать корневой сертификат"; exit;
fi
time aktool k -v public-ca.crt --verbose
#
sudo aktool k --repo-add public-ca.crt
if [[ $? -ne 0 ]]
then echo "aktool не может добавить корневой сертификат в хранилище"; exit;
fi
echo "";
#
#
# теперь вырабатываем сертификат УЦ первого уровня
aktool k -nt sign512 --curve ec512b -o secret-l1.key --op public-l1.csr --id "Aktool Level I" --to pem --outpass 321azO
if [[ $? -ne 0 ]]
then echo "aktool не может создать запрос на сертификат"; exit;
fi
aktool k -c public-l1.csr --op public-l1.crt --to pem --ca-key secret-ca.key --inpass 321azO --ca-cert public-ca.crt --days 1 --ca-ext true --key-cert-sign
if [[ $? -ne 0 ]]
then echo "aktool не может создать сертификат"; exit;
fi
time aktool k -v public-l1.crt
#
sudo aktool k --repo-add public-l1.crt
if [[ $? -ne 0 ]]
then echo "aktool не может добавить сертификат удостоверяющего центра первого уровня в хранилище"; exit;
fi
echo "";
#
#
# теперь вырабатываем сертификат УЦ второго уровня
aktool k -nt sign512 --curve ec512a -o secret-l2.key --op public-l2.csr --id "Aktool Level II" --to pem --outpass 321azO
if [[ $? -ne 0 ]]
then echo "aktool не может создать запрос на сертификат"; exit;
fi
aktool k -c public-l2.csr --op public-l2.crt --to pem --ca-key secret-l1.key --inpass 321azO --ca-cert public-l1.crt --days 1 --ca-ext true --key-cert-sign
if [[ $? -ne 0 ]]
then echo "aktool не может создать сертификат"; exit;
fi
time aktool k -v public-l2.crt
#
sudo aktool k --repo-add public-l2.crt
if [[ $? -ne 0 ]]
then echo "aktool не может добавить сертификат удостоверяющего центра второго уровня в хранилище"; exit;
fi
echo "";


# на-последок, показываем, что натворили и удаляем созданные файлы
aktool k --repo-show
#rm -f secret-ca.key public-ca.crt
#rm -f secret-l1.key public-l1.csr public-l1.crt
#rm -f secret-l2.key public-l2.csr public-l2.crt
