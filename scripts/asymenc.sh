# /bin/bash
#
# 1. Создаем ключи центра сертификации
aktool k -nt sign512 --curve ec512b --ca -o ca.key --outpass z12Ajq --op ca.crt --to certificate --id "Root CA"
#
# 2. Создаем ключевую пару для получателя сообщений
aktool k -nt sign256 -o user.key --outpass 1Qlm!21 --op user_request.csr --to pem --id "Local User"
aktool k -v user_request.csr
aktool k -s user.key
#
# 3. Вырабатываем сертификат пользователя 
aktool k -c user_request.csr --key-encipherment --secret-key-number `aktool k --show-number user.key` --ca-key ca.key --inpass z12Ajq --ca-cert ca.crt --op user.crt --to pem
aktool k -v user.crt --ca-cert ca.crt --verbose



# В завершение теста, удаляем созданные файлы
rm -f ca.key ca.crt user_request.csr user.key user.crt

