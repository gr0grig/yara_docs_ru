# Модуль dotnet

*Добавлен в версии 3.6.0*

Модуль dotnet позволяет создавать более точные правила для .NET-файлов, используя атрибуты и особенности формата .NET. Рассмотрим примеры:

```yara
import "dotnet"

rule not_exactly_five_streams
{
    condition:
        dotnet.number_of_streams != 5
}

rule blop_stream
{
    condition:
        for any i in (0..dotnet.number_of_streams - 1):
            (dotnet.streams[i].name == "#Blop")
}
```

## Справочник

### version

Строка версии, содержащаяся в корне метаданных.

*Пример: dotnet.version == "v2.0.50727"*

### module_name

Имя модуля.

*Пример: dotnet.module_name == "axs"*

### number_of_streams

Количество потоков (streams) в файле.

### streams

Массив объектов потоков с нулевой индексацией. Каждый объект потока имеет следующие атрибуты:

- **name** — Имя потока.
- **offset** — Смещение потока.
- **size** — Размер потока.

*Пример: dotnet.streams[0].name == "#~"*

### number_of_guids

Количество GUID в массиве guids.

### guids

Массив строк с нулевой индексацией, по одной для каждого GUID.

*Пример: dotnet.guids[0] == "99c08ffd-f378-a891-10ab-c02fe11be6ef"*

### number_of_classes

Количество классов в файле.

### classes

Массив .NET-классов, хранящихся в метаданных. Каждый объект класса содержит следующие атрибуты:

- **fullname** — Полное имя класса.
- **name** — Имя класса.
- **namespace** — Пространство имён класса.
- **visibility** — Спецификатор видимости: `private`, `public`, `protected`, `internal`, `private protected`, `protected internal`.
- **type** — Тип объекта: `class`, `interface`.
- **abstract** — Булево значение, является ли класс абстрактным.
- **sealed** — Булево значение, является ли класс запечатанным.
- **number_of_generic_parameters** — Количество обобщённых параметров.
- **generic_parameters** — Массив имён обобщённых параметров с нулевой индексацией.
- **number_of_base_types** — Количество базовых типов.
- **base_types** — Массив имён базовых типов с нулевой индексацией.
- **number_of_methods** — Количество методов.
- **methods** — Массив объектов методов с нулевой индексацией. Каждый объект содержит:
  - **name** — Имя метода.
  - **visibility** — Спецификатор видимости: `private`, `public`, `protected`, `internal`, `private protected`, `protected internal`.
  - **static** — Булево значение, является ли метод статическим.
  - **virtual** — Булево значение, является ли метод виртуальным.
  - **final** — Булево значение, является ли метод финальным.
  - **abstract** — Булево значение, является ли метод абстрактным.
  - **return_type** — Имя возвращаемого типа метода.
  - **number_of_parameters** — Количество параметров метода.
  - **parameters** — Массив параметров метода с нулевой индексацией. Каждый параметр содержит:
    - **name** — Имя параметра.
    - **type** — Тип параметра.
  - **number_of_generic_parameters** — Количество обобщённых параметров метода.
  - **generic_parameters** — Массив обобщённых параметров метода с нулевой индексацией.

*Пример: dotnet.classes[0].fullname == "Launcher.Program"*

### number_of_resources

Количество ресурсов в .NET-файле. Они отличаются от обычных PE-ресурсов.

### resources

Массив объектов ресурсов с нулевой индексацией. Каждый объект имеет следующие атрибуты:

- **offset** — Смещение данных ресурса.
- **length** — Длина данных ресурса.
- **name** — Имя ресурса (строка).

*Пример: uint16be(dotnet.resources[0].offset) == 0x4d5a*

### assembly

Объект с информацией о сборке .NET.

- **version** — Объект с целочисленными значениями, представляющими информацию о версии сборки. Атрибуты: `major`, `minor`, `build_number`, `revision_number`.
- **name** — Строка с именем сборки.
- **culture** — Строка с культурой (язык/страна/регион) для данной сборки.

*Пример: dotnet.assembly.name == "Keylogger"*

*Пример: dotnet.assembly.version.major == 7 and dotnet.assembly.version.minor == 0*

### number_of_modulerefs

Количество ссылок на модули в .NET-файле.

### modulerefs

Массив строк с нулевой индексацией, по одной для каждой ссылки на модуль.

*Пример: dotnet.modulerefs[0] == "kernel32"*

### typelib

Библиотека типов файла.

### number_of_constants

Количество констант в .NET-файле.

### constants

Массив строк с нулевой индексацией, по одной для каждой константы.

### number_of_assembly_refs

Количество объектов со ссылками на сборки .NET.

### assembly_refs

Объект со ссылками на сборки .NET.

- **version** — Объект с целочисленными значениями версии. Атрибуты: `major`, `minor`, `build_number`, `revision_number`.
- **name** — Строка с именем сборки.
- **public_key_or_token** — Строка с открытым ключом или токеном, идентифицирующим автора сборки.

### number_of_user_strings

Количество пользовательских строк в файле.

### user_strings

Массив пользовательских строк с нулевой индексацией.

### number_of_field_offsets

Количество полей в массиве field_offsets.

### field_offsets

Массив целых чисел с нулевой индексацией, по одному для каждого поля.

*Пример: dotnet.field_offsets[0] == 8675309*

### is_dotnet

*Добавлен в версии 4.2.0*

Функция, возвращающая true, если PE-файл действительно является .NET.

*Пример: dotnet.is_dotnet*
