# Модуль Magic

*Добавлен в версии 3.1.0*

Модуль Magic позволяет определять тип файла на основе вывода команды [file](http://en.wikipedia.org/wiki/File_(command)) — стандартной Unix-утилиты.

> **Важно:** Этот модуль не включён в YARA по умолчанию. Чтобы узнать, как его включить, обратитесь к разделу [Компиляция YARA](../gettingstarted.md). **Этот модуль не поддерживается на Windows.**

В модуле есть две функции: `type()` и `mime_type()`. Первая возвращает описательную строку, выдаваемую программой *file*. Например, если вы запустите *file* для PDF-документа, вы получите что-то вроде:

```
$ file some.pdf
some.pdf: PDF document, version 1.5
```

Функция `type()` в этом случае вернёт *"PDF document, version 1.5"*. Использование функции `mime_type()` аналогично передаче аргумента `--mime` команде *file*:

```
$ file --mime some.pdf
some.pdf: application/pdf; charset=binary
```

`mime_type()` вернёт *"application/pdf"*, без части charset.

Экспериментируя с командой *file*, вы узнаете, какой вывод ожидать для разных типов файлов. Вот несколько примеров:

* JPEG image data, JFIF standard 1.01
* PE32 executable for MS Windows (GUI) Intel 80386 32-bit
* PNG image data, 1240 x 1753, 8-bit/color RGBA, non-interlaced
* ASCII text, with no line terminators
* Zip archive data, at least v2.0 to extract

libmagic по умолчанию пытается прочитать свою скомпилированную базу типов файлов из /etc/magic.mgc. Если этот файл не существует, вы можете установить переменную окружения MAGIC, указывающую на файл magic.mgc, и libmagic попытается загрузить его оттуда.

## Справочник

### type()

Функция, возвращающая строку с типом файла.

*Пример: magic.type() contains "PDF"*

### mime_type()

Функция, возвращающая строку с MIME-типом файла.

*Пример: magic.mime_type() == "application/pdf"*
