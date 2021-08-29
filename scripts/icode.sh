##########################################################################
#! /bin/bash
#
# скрипт проверяет все возможные способы
# генерации и проверки кодов целостности
#
##########################################################################
echo "Тестируем функции хэширования"
aktool i . --tag -o result.streebog256
if [[ $? -ne 0 ]]
then echo "aktool не может посчитать значения функции хеширования"; exit;
fi
echo "Ok (Стрибог256)";
cat result.streebog256
aktool i -c result.streebog256 --ignore-errors
if [[ $? -ne 0 ]]
then echo "aktool не может проверить значения функции хеширования"; exit;
fi
#
aktool i -a streebog512 -p "*.s?" . -o result.streebog512
if [[ $? -ne 0 ]]
then echo "aktool не может посчитать значения функции хеширования Стрибог512"; exit;
fi
echo "Ok (Стрибог512)";
cat result.streebog512
aktool i -c result.streebog512 -a streebog512 --ignore-errors
if [[ $? -ne 0 ]]
then echo "aktool не может проверить значения функции хеширования"; exit;
fi
#
#
echo; echo "Тестируем алгоритмы hmac"
aktool k -nt hmac-streebog256 -o hmac256.key --outpass 132a
if [[ $? -ne 0 ]]
then echo "aktool не может создать ключ алгоритма hmac"; exit;
fi
echo;
aktool i --key hmac256.key --inpass 132a --tag . -o result.hmac-streebog256
if [[ $? -ne 0 ]]
then echo "aktool не может вычислить имитовставки"; exit;
fi
cat result.hmac-streebog256
aktool i -c result.hmac-streebog256 --key hmac256.key --inpass 132a
if [[ $? -ne 0 ]]
then echo "aktool не может проверить имитовставки"; exit;
fi
echo;
#
#
aktool k -nt hmac-streebog512 -o hmac512.key --outpass 132a
if [[ $? -ne 0 ]]
then echo "aktool не может создать ключ алгоритма hmac"; exit;
fi
echo;
aktool i --key hmac512.key --inpass 132a * -o result.hmac-streebog512
if [[ $? -ne 0 ]]
then echo "aktool не может вычислить имитовставки"; exit;
fi
cat result.hmac-streebog512
aktool i -c result.hmac-streebog512 --key hmac512.key --inpass 132a
if [[ $? -ne 0 ]]
then echo "aktool не может проверить имитовставки"; exit;
fi
echo;
#
#
echo; echo "Тестируем алгоритмы выработки имитовставки с использованием шифра Магма"
aktool k -nt magma -o magma.key --outpass 123
if [[ $? -ne 0 ]]
then echo "aktool не может создать ключ алгоритма Магма"; exit;
fi
aktool i --key magma.key -m cmac-magma --inpass 123 * -o result.magma
if [[ $? -ne 0 ]]
then echo "aktool не может выработать имитовставки для алгоритма cmac-magma"; exit;
fi
echo
cat result.magma
aktool i -c result.magma --key magma.key -m cmac-magma --inpass 123
if [[ $? -ne 0 ]]
then echo "aktool не может проверить имитовставки для алгоритма cmac-magma"; exit;
fi
echo
#
#
echo; echo "Тестируем алгоритмы выработки имитовставки с использованием шифра Кузнечик"
aktool k -nt kuznechik -o kuznechik.key --outpass 123
if [[ $? -ne 0 ]]
then echo "aktool не может создать ключ алгоритма Кузнечик"; exit;
fi
aktool i --key kuznechik.key -m cmac-kuznechik --inpass 123 --tag * -o result.kuznechik
if [[ $? -ne 0 ]]
then echo "aktool не может выработать имитовставки для алгоритма cmac-kuznechik"; exit;
fi
echo
cat result.kuznechik
aktool i -c result.kuznechik --key kuznechik.key -m cmac-kuznechik --inpass 123
if [[ $? -ne 0 ]]
then echo "aktool не может проверить имитовставки для алгоритма cmac-kuznechik"; exit;
fi
echo
rm -f magma.key kuznechik.key hmac256.key hmac512.key
rm -f result.*
