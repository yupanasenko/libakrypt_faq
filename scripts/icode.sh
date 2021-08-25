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
#
aktool i -a streebog512 -p "*.s?" . -o result.streebog512
if [[ $? -ne 0 ]]
then echo "aktool не может посчитать значения функции хеширования Стрибог512"; exit;
fi
echo "Ok (Стрибог512)";
cat result.streebog512
exit
#
#
# тестируем алгоритмы hmac
#aktool k -nt hmac-streebog256 -o hmac256.key --outpass QX132a
#aktool i --key hmac256.key --inpass QX132a .
#echo;
#
#aktool k -nt hmac-streebog512 -o hmac512.key --outpass QX132a
#aktool i --key hmac512.key --inpass QX132a .
#echo;
#
#
# тестируем алгоритмы cmac
aktool k -nt magma -o magma.key --outpass 123
echo;
aktool i --key magma.key --inpass 123 * --tag
echo;
aktool i -a magma --inpass 123 --salt 456 *
echo;
#
aktool k -nt kuznechik -o kuznechik.key --outpass 123
echo;
aktool i --key kuznechik.key --inpass 123 *
echo;
aktool i -a kuznechik --inpass 123 .
echo;
#
rm -f magma.key kuznechik.key hmac256.key hmac512.key
rm -f result.streebog256 result.streebog512
