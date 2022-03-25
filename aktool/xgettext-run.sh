# /bin/bash
touch aktool.pot
xgettext aktool.c -a -j --from-code utf-8 -o aktool.pot --msgid-bugs-address='Axel Kenzo <axelkenzo@mail.ru' --package-name='aktool'
msgmerge aktool.po aktool.pot -o aktool.po
rm aktool.pot
