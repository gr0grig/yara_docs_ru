# Модуль Cuckoo

Модуль Cuckoo позволяет создавать правила YARA на основе поведенческой информации, генерируемой [песочницей Cuckoo](https://cuckoosandbox.org/). При сканировании PE-файла с помощью YARA вы можете передать дополнительную информацию о его поведении модулю `cuckoo` и создавать правила, основанные не только на том, что файл *содержит*, но и на том, что он *делает*.

> **Важно:** Этот модуль не включён в YARA по умолчанию. Чтобы узнать, как его включить, обратитесь к разделу [Компиляция YARA](../gettingstarted.md). Для пользователей Windows: этот модуль уже включён в официальные бинарные файлы для Windows.

Предположим, вы заинтересованы в исполняемых файлах, отправляющих HTTP-запрос на http://someone.doingevil.com. В предыдущих версиях YARA приходилось довольствоваться:

```yara
rule evil_doer
{
    strings:
        $evil_domain = "http://someone.doingevil.com"

    condition:
        $evil_domain
}
```

Проблема этого правила в том, что доменное имя может содержаться в файле по вполне легитимным причинам, не связанным с отправкой HTTP-запросов. Кроме того, вредоносный исполняемый файл может содержать доменное имя в зашифрованном или обфусцированном виде, и тогда правило будет бесполезным.

Но теперь с модулем `cuckoo` вы можете взять отчёт о поведении, сгенерированный песочницей Cuckoo, передать его вместе с исполняемым файлом в YARA и написать правило так:

```yara
import "cuckoo"

rule evil_doer
{
    condition:
        cuckoo.network.http_request(/http:\/\/someone\.doingevil\.com/)
}
```

Конечно, вы можете комбинировать условия, связанные с поведением, с обычными условиями на основе строк:

```yara
import "cuckoo"

rule evil_doer
{
    strings:
        $some_string = { 01 02 03 04 05 06 }

    condition:
        $some_string and
        cuckoo.network.http_request(/http:\/\/someone\.doingevil\.com/)
}
```

Как передать информацию о поведении модулю `cuckoo`? В случае инструмента командной строки используйте опцию `-x`:

```
$ yara -x cuckoo=behavior_report_file rules_file pe_file
```

`behavior_report_file` — это путь к файлу с отчётом о поведении, сгенерированным песочницей Cuckoo в формате JSON.

Если вы используете `yara-python`, передайте отчёт о поведении через аргумент `modules_data` метода `match`:

```python
import yara
rules = yara.compile('./rules_file')
report_file = open('./behavior_report_file')
report_data = report_file.read()
rules.match(pe_file, modules_data={'cuckoo': bytes(report_data)})
```

## Справочник

### network

#### http_request(regexp)

Функция, возвращающая true, если программа отправила HTTP-запрос на URL, соответствующий указанному регулярному выражению.

*Пример: cuckoo.network.http_request(/evil\\.com/)*

#### http_get(regexp)

Аналогична `http_request`, но учитывает только GET-запросы.

#### http_post(regexp)

Аналогична `http_request`, но учитывает только POST-запросы.

#### http_user_agent(regexp)

Функция, возвращающая true, если программа отправила HTTP-запрос с user agent, соответствующим указанному регулярному выражению.

*Пример: cuckoo.network.http_user_agent(/MSIE 6\\.0/)*

#### dns_lookup(regexp)

Функция, возвращающая true, если программа отправила запрос на разрешение доменного имени, соответствующего указанному регулярному выражению.

*Пример: cuckoo.network.dns_lookup(/evil\\.com/)*

#### host(regexp)

Функция, возвращающая true, если программа связалась с IP-адресом, соответствующим указанному регулярному выражению.

*Пример: cuckoo.network.host(/192\\.168\\.1\\.1/)*

#### tcp(regexp, port)

Функция, возвращающая true, если программа связалась с IP-адресом, соответствующим указанному регулярному выражению, по протоколу TCP на указанном порту.

*Пример: cuckoo.network.tcp(/192\\.168\\.1\\.1/, 443)*

#### udp(regexp, port)

Функция, возвращающая true, если программа связалась с IP-адресом, соответствующим указанному регулярному выражению, по протоколу UDP на указанном порту.

*Пример: cuckoo.network.udp(/192\\.168\\.1\\.1/, 53)*

### registry

#### key_access(regexp)

Функция, возвращающая true, если программа обращалась к записи реестра, соответствующей указанному регулярному выражению.

*Пример: cuckoo.registry.key_access(/\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run/)*

### filesystem

#### file_access(regexp)

Функция, возвращающая true, если программа обращалась к файлу, соответствующему указанному регулярному выражению.

*Пример: cuckoo.filesystem.file_access(/autoexec\\.bat/)*

### sync

#### mutex(regexp)

Функция, возвращающая true, если программа открывала или создавала мьютекс, соответствующий указанному регулярному выражению.

*Пример: cuckoo.sync.mutex(/EvilMutexName/)*
