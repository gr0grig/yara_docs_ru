# Начало работы

YARA — это мультиплатформенная программа, работающая на Windows, Linux и Mac OS X. Последний релиз можно найти по адресу https://github.com/VirusTotal/yara/releases.

## Компиляция и установка YARA

Скачайте архив с исходным кодом и подготовьтесь к компиляции:

```
tar -zxf yara-4.5.0.tar.gz
cd yara-4.5.0
./bootstrap.sh
```

Убедитесь, что в вашей системе установлены `automake`, `libtool`, `make`, `gcc` и `pkg-config`. Пользователи Ubuntu и Debian могут использовать:

```
sudo apt-get install automake libtool make gcc pkg-config
```

Если вы планируете модифицировать исходный код YARA, вам также могут понадобиться `flex` и `bison` для генерации лексеров и парсеров:

```
sudo apt-get install flex bison
```

Скомпилируйте и установите YARA стандартным способом:

```
./bootstrap.sh
./configure
make
sudo make install
```

Запустите тесты, чтобы убедиться, что всё работает корректно:

```
make check
```

Некоторые функции YARA зависят от библиотеки OpenSSL. Эти функции включаются только при наличии библиотеки OpenSSL в вашей системе. Если её нет, YARA будет работать нормально, но вы не сможете использовать отключённые функции. Скрипт `configure` автоматически определяет, установлена ли OpenSSL. Если вы хотите принудительно включить функции, зависящие от OpenSSL, передайте `--with-crypto` скрипту `configure`. Пользователи Ubuntu и Debian могут установить библиотеку OpenSSL командой `sudo apt-get install libssl-dev`.

Следующие модули не компилируются в YARA по умолчанию:

* cuckoo
* magic

Если вы планируете их использовать, необходимо передать соответствующие аргументы `--enable-<имя модуля>` скрипту `configure`.

Например:

```
./configure --enable-cuckoo
./configure --enable-magic
./configure --enable-cuckoo --enable-magic
```

Модули обычно зависят от внешних библиотек. В зависимости от выбранных модулей вам понадобятся следующие библиотеки:

* **cuckoo**: Зависит от [Jansson](http://www.digip.org/jansson/) для разбора JSON. Некоторые версии Ubuntu и Debian уже содержат пакет `libjansson-dev`. Если `sudo apt-get install libjansson-dev` не работает, получите исходный код из [репозитория](https://github.com/akheron/jansson).

* **magic**: Зависит от *libmagic* — библиотеки, используемой стандартной Unix-программой [file](http://en.wikipedia.org/wiki/File_(command)). Ubuntu, Debian и CentOS содержат пакет `libmagic-dev`. Исходный код можно найти [здесь](ftp://ftp.astron.com/pub/file/).

### Установка через vcpkg

Вы также можете скачать и установить YARA с помощью менеджера зависимостей [vcpkg](https://github.com/Microsoft/vcpkg/):

```
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
./bootstrap-vcpkg.sh
./vcpkg integrate install
vcpkg install yara
```

Порт YARA в vcpkg поддерживается командой Microsoft и участниками сообщества. Если версия устарела, пожалуйста, [создайте issue или pull request](https://github.com/Microsoft/vcpkg/) в репозитории vcpkg.

### Установка на Windows

Скомпилированные бинарные файлы для Windows в 32-битной и 64-битной версиях можно найти по ссылке ниже. Просто скачайте нужную версию, распакуйте архив и поместите файлы `yara.exe` и `yarac.exe` в любое место на диске.

[Скачать бинарные файлы для Windows](https://github.com/VirusTotal/yara/releases/latest)

Для установки YARA с помощью [Scoop](https://scoop.sh) или [Chocolatey](https://chocolatey.org) просто введите `scoop install yara` или `choco install yara`. Интеграция с Scoop и Chocolatey поддерживается их командами, а не авторами YARA.

### Установка на Mac OS X через Homebrew

Для установки YARA с помощью [Homebrew](https://brew.sh) просто введите `brew install yara`.

### Установка yara-python

Если вы планируете использовать YARA из Python-скриптов, вам необходимо установить расширение `yara-python`. Инструкции по установке см. на https://github.com/VirusTotal/yara-python.

## Первый запуск YARA

Теперь, когда вы установили YARA, можно написать очень простое правило и использовать инструмент командной строки для сканирования файла:

```sh
echo "rule dummy { condition: true }" > my_first_rule
yara my_first_rule my_first_rule
```

Не путайтесь из-за повторяющегося `my_first_rule` в аргументах `yara` — я просто передаю один и тот же файл и как правила, и как файл для сканирования. Вы можете указать любой файл для сканирования (второй аргумент).

Если всё прошло нормально, вы получите следующий вывод:

```
dummy my_first_rule
```

Это означает, что файл `my_first_rule` соответствует правилу с именем `dummy`.

Если вы получили ошибку вида:

```
yara: error while loading shared libraries: libyara.so.2: cannot open shared
object file: No such file or directory
```

Это означает, что загрузчик не может найти библиотеку `libyara`, расположенную в `/usr/local/lib`. В некоторых дистрибутивах Linux загрузчик по умолчанию не ищет библиотеки по этому пути. Необходимо указать ему делать это, добавив `/usr/local/lib` в файл конфигурации загрузчика `/etc/ld.so.conf`:

```
sudo sh -c 'echo "/usr/local/lib" >> /etc/ld.so.conf'
sudo ldconfig
```

В новых выпусках Ubuntu, таких как 22.04 LTS, корректная конфигурация загрузчика устанавливается через зависимости в `/etc/ld.so.conf.d/libc.conf`. В этом случае достаточно выполнить только следующую команду для настройки привязок динамического компоновщика:

```
sudo ldconfig
```

Если вы используете Windows PowerShell в качестве командной оболочки, `yara my_first_rule my_first_rule` может вернуть ошибку:

```
my_first_rule(1): error: non-ascii character
```

Вы можете избежать этого, используя командлет `Set-Content` для указания ASCII-кодировки при создании файла с правилом:

```powershell
Set-Content -path .\my_first_rule -Value "rule dummy { condition: true }" -Encoding Ascii
.\yara my_first_rule my_first_rule
```
