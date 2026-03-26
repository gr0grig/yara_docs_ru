# Модуль PE

Модуль PE позволяет создавать более точные правила для PE-файлов, используя атрибуты и особенности формата PE-файлов. Этот модуль предоставляет доступ к большинству полей, присутствующих в заголовке PE, и предоставляет функции, которые можно использовать для написания более выразительных и целенаправленных правил. Рассмотрим несколько примеров:

```yara
import "pe"

rule single_section
{
    condition:
        pe.number_of_sections == 1
}

rule control_panel_applet
{
    condition:
        pe.exports("CPlApplet")
}

rule is_dll
{
    condition:
        pe.characteristics & pe.DLL
}

rule is_pe
{
    condition:
        pe.is_pe
}
```

## Справочник

### machine

*Изменено в версии 3.3.0*

Целое число с одним из следующих значений:

- `MACHINE_UNKNOWN`
- `MACHINE_AM33`
- `MACHINE_AMD64`
- `MACHINE_ARM`
- `MACHINE_ARMNT`
- `MACHINE_ARM64`
- `MACHINE_EBC`
- `MACHINE_I386`
- `MACHINE_IA64`
- `MACHINE_M32R`
- `MACHINE_MIPS16`
- `MACHINE_MIPSFPU`
- `MACHINE_MIPSFPU16`
- `MACHINE_POWERPC`
- `MACHINE_POWERPCFP`
- `MACHINE_R4000`
- `MACHINE_SH3`
- `MACHINE_SH3DSP`
- `MACHINE_SH4`
- `MACHINE_SH5`
- `MACHINE_THUMB`
- `MACHINE_WCEMIPSV2`
- `MACHINE_TARGET_HOST`
- `MACHINE_R3000`
- `MACHINE_R10000`
- `MACHINE_ALPHA`
- `MACHINE_SH3E`
- `MACHINE_ALPHA64`
- `MACHINE_AXP64`
- `MACHINE_TRICORE`
- `MACHINE_CEF`
- `MACHINE_CEE`

*Пример: pe.machine == pe.MACHINE_AMD64*

### checksum

*Добавлено в версии 3.6.0*

Целое число, содержащее "контрольную сумму PE", хранящуюся в OptionalHeader.

### calculate_checksum

*Добавлено в версии 3.6.0*

Функция, вычисляющая "контрольную сумму PE".

*Пример: pe.checksum == pe.calculate_checksum()*

### subsystem

Целое число с одним из следующих значений:

- `SUBSYSTEM_UNKNOWN`
- `SUBSYSTEM_NATIVE`
- `SUBSYSTEM_WINDOWS_GUI`
- `SUBSYSTEM_WINDOWS_CUI`
- `SUBSYSTEM_OS2_CUI`
- `SUBSYSTEM_POSIX_CUI`
- `SUBSYSTEM_NATIVE_WINDOWS`
- `SUBSYSTEM_WINDOWS_CE_GUI`
- `SUBSYSTEM_EFI_APPLICATION`
- `SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER`
- `SUBSYSTEM_EFI_RUNTIME_DRIVER`
- `SUBSYSTEM_EFI_ROM_IMAGE`
- `SUBSYSTEM_XBOX`
- `SUBSYSTEM_WINDOWS_BOOT_APPLICATION`

*Пример: pe.subsystem == pe.SUBSYSTEM_NATIVE*

### timestamp

Временная метка PE в виде целого числа (epoch).

*Пример: pe.timestamp >= 1424563200*

### pointer_to_symbol_table

*Добавлено в версии 3.8.0*

Значение IMAGE_FILE_HEADER::PointerToSymbolTable. Используется, когда PE-образ содержит отладочную информацию COFF.

### number_of_symbols

*Добавлено в версии 3.8.0*

Значение IMAGE_FILE_HEADER::NumberOfSymbols. Используется, когда PE-образ содержит отладочную информацию COFF.

### size_of_optional_header

*Добавлено в версии 3.8.0*

Значение IMAGE_FILE_HEADER::SizeOfOptionalHeader. Это реальный размер необязательного заголовка, отражающий различия между 32-битным и 64-битным необязательными заголовками и количество каталогов данных.

### opthdr_magic

*Добавлено в версии 3.8.0*

Значение IMAGE_OPTIONAL_HEADER::Magic.

Целое число с одним из следующих значений:

- `IMAGE_NT_OPTIONAL_HDR32_MAGIC`
- `IMAGE_NT_OPTIONAL_HDR64_MAGIC`
- `IMAGE_ROM_OPTIONAL_HDR_MAGIC`

### size_of_code

*Добавлено в версии 3.8.0*

Значение IMAGE_OPTIONAL_HEADER::SizeOfCode. Это сумма размеров необработанных данных в секциях кода.

### size_of_initialized_data

*Добавлено в версии 3.8.0*

Значение IMAGE_OPTIONAL_HEADER::SizeOfInitializedData.

### size_of_uninitialized_data

Значение IMAGE_OPTIONAL_HEADER::SizeOfUninitializedData.

### entry_point

Смещение точки входа в файле или виртуальный адрес, в зависимости от того, сканирует ли YARA файл или память процесса соответственно. Это эквивалент устаревшего ключевого слова `entrypoint`.

### entry_point_raw

*Добавлено в версии 4.1.0*

Необработанное значение точки входа из необязательного заголовка PE. Это значение не преобразуется в смещение файла или RVA.

### base_of_code

*Добавлено в версии 3.8.0*

Значение IMAGE_OPTIONAL_HEADER::BaseOfCode.

### base_of_data

*Добавлено в версии 3.8.0*

Значение IMAGE_OPTIONAL_HEADER::BaseOfData. Это поле существует только в 32-битных PE-файлах.

### image_base

Относительный виртуальный адрес базы образа.

### section_alignment

*Добавлено в версии 3.8.0*

Значение IMAGE_OPTIONAL_HEADER::SectionAlignment. Когда Windows загружает PE-образ в память, все необработанные размеры (включая размер заголовка) выравниваются до этого значения.

### file_alignment

*Добавлено в версии 3.8.0*

Значение IMAGE_OPTIONAL_HEADER::FileAlignment. Все размеры необработанных данных секций в PE-образе выравниваются до этого значения.

### win32_version_value

*Добавлено в версии 3.8.0*

Значение IMAGE_OPTIONAL_HEADER::Win32VersionValue.

### size_of_image

*Добавлено в версии 3.8.0*

Значение IMAGE_OPTIONAL_HEADER::SizeOfImage. Это общий виртуальный размер заголовка и всех секций.

### size_of_headers

*Добавлено в версии 3.8.0*

Значение IMAGE_OPTIONAL_HEADER::SizeOfHeaders. Это размер необработанных данных заголовков PE, включая DOS-заголовок, файловый заголовок, необязательный заголовок и все заголовки секций. При загрузке PE в память это значение выравнивается до SectionAlignment.

### characteristics

Битовая карта характеристик файлового заголовка PE (FileHeader). Отдельные характеристики можно проверить с помощью побитовой операции И со следующими константами:

- `RELOCS_STRIPPED` -- Информация о перемещениях удалена из файла.
- `EXECUTABLE_IMAGE` -- Файл является исполняемым (т.е. нет неразрешённых внешних ссылок).
- `LINE_NUMS_STRIPPED` -- Номера строк удалены из файла.
- `LOCAL_SYMS_STRIPPED` -- Локальные символы удалены из файла.
- `AGGRESIVE_WS_TRIM` -- Агрессивное сокращение рабочего набора.
- `LARGE_ADDRESS_AWARE` -- Приложение может работать с адресами >2 ГБ.
- `BYTES_REVERSED_LO` -- Байты машинного слова переставлены.
- `MACHINE_32BIT` -- 32-битная машина.
- `DEBUG_STRIPPED` -- Отладочная информация удалена из файла в файл .DBG.
- `REMOVABLE_RUN_FROM_SWAP` -- Если образ на съёмном носителе, скопировать и запустить из файла подкачки.
- `NET_RUN_FROM_SWAP` -- Если образ в сети, скопировать и запустить из файла подкачки.
- `SYSTEM` -- Системный файл.
- `DLL` -- Файл является DLL.
- `UP_SYSTEM_ONLY` -- Файл должен запускаться только на однопроцессорной машине.
- `BYTES_REVERSED_HI` -- Байты машинного слова переставлены.

*Пример: pe.characteristics & pe.DLL*

### linker_version

Объект с двумя целочисленными атрибутами, по одному для основной и дополнительной версии компоновщика.

- `major` -- Основная версия компоновщика.
- `minor` -- Дополнительная версия компоновщика.

### os_version

Объект с двумя целочисленными атрибутами, по одному для основной и дополнительной версии ОС.

- `major` -- Основная версия ОС.
- `minor` -- Дополнительная версия ОС.

### image_version

Объект с двумя целочисленными атрибутами, по одному для основной и дополнительной версии образа.

- `major` -- Основная версия образа.
- `minor` -- Дополнительная версия образа.

### subsystem_version

Объект с двумя целочисленными атрибутами, по одному для основной и дополнительной версии подсистемы.

- `major` -- Основная версия подсистемы.
- `minor` -- Дополнительная версия подсистемы.

### dll_characteristics

Битовая карта DllCharacteristics из OptionalHeader PE. Не путайте эти флаги с характеристиками файлового заголовка PE (FileHeader Characteristics). Отдельные характеристики можно проверить с помощью побитовой операции И со следующими константами:

- `HIGH_ENTROPY_VA` -- ASLR с 64-битным адресным пространством.
- `DYNAMIC_BASE` -- Файл может быть перемещён -- также помечает файл как совместимый с ASLR.
- `FORCE_INTEGRITY`
- `NX_COMPAT` -- Помечает файл как совместимый с DEP.
- `NO_ISOLATION`
- `NO_SEH` -- Файл не содержит обработчиков структурных исключений; это должно быть установлено для использования SafeSEH.
- `NO_BIND`
- `APPCONTAINER` -- Образ должен выполняться в AppContainer.
- `WDM_DRIVER` -- Помечает файл как драйвер модели Windows Driver Model (WDM).
- `GUARD_CF` -- Образ поддерживает Control Flow Guard.
- `TERMINAL_SERVER_AWARE` -- Помечает файл как совместимый с терминальным сервером.

### size_of_stack_reserve

*Добавлено в версии 3.8.0*

Значение IMAGE_OPTIONAL_HEADER::SizeOfStackReserve. Это объём виртуальной памяти по умолчанию, который будет зарезервирован для стека.

### size_of_stack_commit

*Добавлено в версии 3.8.0*

Значение IMAGE_OPTIONAL_HEADER::SizeOfStackCommit. Это объём виртуальной памяти по умолчанию, который будет выделен для стека.

### size_of_heap_reserve

*Добавлено в версии 3.8.0*

Значение IMAGE_OPTIONAL_HEADER::SizeOfHeapReserve. Это объём виртуальной памяти по умолчанию, который будет зарезервирован для основной кучи процесса.

### size_of_heap_commit

*Добавлено в версии 3.8.0*

Значение IMAGE_OPTIONAL_HEADER::SizeOfHeapCommit. Это объём виртуальной памяти по умолчанию, который будет выделен для основной кучи процесса.

### loader_flags

*Добавлено в версии 3.8.0*

Значение IMAGE_OPTIONAL_HEADER::LoaderFlags.

### number_of_rva_and_sizes

Значение IMAGE_OPTIONAL_HEADER::NumberOfRvaAndSizes. Это количество элементов в массиве IMAGE_OPTIONAL_HEADER::DataDirectory.

### data_directories

*Добавлено в версии 3.8.0*

Массив каталогов данных с нумерацией от нуля. Каждый каталог данных содержит виртуальный адрес и длину соответствующего каталога данных. Каждый каталог данных имеет следующие поля:

- `virtual_address` -- Относительный виртуальный адрес (RVA) каталога данных PE. Если он равен нулю, то каталог данных отсутствует. Обратите внимание, что для цифровой подписи это смещение в файле, а не RVA.
- `size` -- Размер каталога данных PE в байтах.

Индекс записи каталога данных может принимать одно из следующих значений:

- `IMAGE_DIRECTORY_ENTRY_EXPORT` -- Каталог данных для экспортируемых функций.
- `IMAGE_DIRECTORY_ENTRY_IMPORT` -- Каталог данных для каталога импорта.
- `IMAGE_DIRECTORY_ENTRY_RESOURCE` -- Каталог данных для секции ресурсов.
- `IMAGE_DIRECTORY_ENTRY_EXCEPTION` -- Каталог данных для информации об исключениях.
- `IMAGE_DIRECTORY_ENTRY_SECURITY` -- Это необработанное смещение и длина цифровой подписи образа в файле. Если образ не имеет встроенной цифровой подписи, этот каталог будет содержать нули.
- `IMAGE_DIRECTORY_ENTRY_BASERELOC` -- Каталог данных для таблицы перемещений образа.
- `IMAGE_DIRECTORY_ENTRY_DEBUG` -- Каталог данных для отладочной информации.

  Значения IMAGE_DEBUG_DIRECTORY::Type:

  - `IMAGE_DEBUG_TYPE_UNKNOWN`
  - `IMAGE_DEBUG_TYPE_COFF`
  - `IMAGE_DEBUG_TYPE_CODEVIEW`
  - `IMAGE_DEBUG_TYPE_FPO`
  - `IMAGE_DEBUG_TYPE_MISC`
  - `IMAGE_DEBUG_TYPE_EXCEPTION`
  - `IMAGE_DEBUG_TYPE_FIXUP`
  - `IMAGE_DEBUG_TYPE_OMAP_TO_SRC`
  - `IMAGE_DEBUG_TYPE_OMAP_FROM_SRC`
  - `IMAGE_DEBUG_TYPE_BORLAND`
  - `IMAGE_DEBUG_TYPE_RESERVED10`
  - `IMAGE_DEBUG_TYPE_CLSID`
  - `IMAGE_DEBUG_TYPE_VC_FEATURE`
  - `IMAGE_DEBUG_TYPE_POGO`
  - `IMAGE_DEBUG_TYPE_ILTCG`
  - `IMAGE_DEBUG_TYPE_MPX`
  - `IMAGE_DEBUG_TYPE_REPRO`

- `IMAGE_DIRECTORY_ENTRY_ARCHITECTURE`
- `IMAGE_DIRECTORY_ENTRY_COPYRIGHT`
- `IMAGE_DIRECTORY_ENTRY_TLS` -- Каталог данных для локального хранилища потока (TLS) образа.
- `IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG` -- Каталог данных для конфигурации загрузки образа.
- `IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT` -- Каталог данных для таблицы связанного импорта образа.
- `IMAGE_DIRECTORY_ENTRY_IAT` -- Каталог данных для таблицы адресов импорта (IAT) образа.
- `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT` -- Каталог данных для таблицы отложенного импорта. Структура таблицы отложенного импорта зависит от компоновщика. Версия Microsoft отложенного импорта описана в исходных файлах "delayimp.h" и "delayimp.cpp", которые можно найти в исходных кодах CRT MS Visual Studio 2008.
- `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR` -- Каталог данных для заголовков .NET.

*Пример: pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].virtual_address != 0*

### number_of_sections

Количество секций в PE.

### sections

*Добавлено в версии 3.3.0*

Массив объектов секций с нумерацией от нуля, по одному для каждой секции PE. Доступ к отдельным секциям осуществляется с помощью оператора `[]`. Каждый объект секции имеет следующие атрибуты:

- `name` -- Имя секции.
- `full_name` -- Если имя в таблице секций содержит косую черту (`/`), за которой следует представление десятичного числа в формате ASCII, то это поле содержит строку из указанного смещения в таблице строк. В противном случае это поле содержит то же значение, что и поле name. Хотя это не является стандартом, компиляторы MinGW и Cygwin используют эту возможность для хранения имён секций длиннее 8 символов.
- `characteristics` -- Характеристики секции.
- `virtual_address` -- Виртуальный адрес секции.
- `virtual_size` -- Виртуальный размер секции.
- `raw_data_offset` -- Необработанное смещение секции.
- `raw_data_size` -- Необработанный размер секции.
- `pointer_to_relocations` -- *(Добавлено в версии 3.8.0)* Значение IMAGE_SECTION_HEADER::PointerToRelocations.
- `pointer_to_line_numbers` -- *(Добавлено в версии 3.8.0)* Значение IMAGE_SECTION_HEADER::PointerToLinenumbers.
- `number_of_relocations` -- *(Добавлено в версии 3.8.0)* Значение IMAGE_SECTION_HEADER::NumberOfRelocations.
- `number_of_line_numbers` -- *(Добавлено в версии 3.8.0)* Значение IMAGE_SECTION_HEADER::NumberOfLineNumbers.

*Пример: pe.sections[0].name == ".text"*

Отдельные характеристики секций можно проверить с помощью побитовой операции И со следующими константами:

- `SECTION_NO_PAD`
- `SECTION_CNT_CODE`
- `SECTION_CNT_INITIALIZED_DATA`
- `SECTION_CNT_UNINITIALIZED_DATA`
- `SECTION_LNK_OTHER`
- `SECTION_LNK_INFO`
- `SECTION_LNK_REMOVE`
- `SECTION_LNK_COMDAT`
- `SECTION_NO_DEFER_SPEC_EXC`
- `SECTION_GPREL`
- `SECTION_MEM_FARDATA`
- `SECTION_MEM_PURGEABLE`
- `SECTION_MEM_16BIT`
- `SECTION_LNK_NRELOC_OVFL`
- `SECTION_MEM_LOCKED`
- `SECTION_MEM_PRELOAD`
- `SECTION_ALIGN_1BYTES`
- `SECTION_ALIGN_2BYTES`
- `SECTION_ALIGN_4BYTES`
- `SECTION_ALIGN_8BYTES`
- `SECTION_ALIGN_16BYTES`
- `SECTION_ALIGN_32BYTES`
- `SECTION_ALIGN_64BYTES`
- `SECTION_ALIGN_128BYTES`
- `SECTION_ALIGN_256BYTES`
- `SECTION_ALIGN_512BYTES`
- `SECTION_ALIGN_1024BYTES`
- `SECTION_ALIGN_2048BYTES`
- `SECTION_ALIGN_4096BYTES`
- `SECTION_ALIGN_8192BYTES`
- `SECTION_ALIGN_MASK`
- `SECTION_MEM_DISCARDABLE`
- `SECTION_MEM_NOT_CACHED`
- `SECTION_MEM_NOT_PAGED`
- `SECTION_MEM_SHARED`
- `SECTION_MEM_EXECUTE`
- `SECTION_MEM_READ`
- `SECTION_MEM_WRITE`
- `SECTION_SCALE_INDEX`

*Пример: pe.sections[1].characteristics & pe.SECTION_CNT_CODE*

### overlay

*Добавлено в версии 3.6.0*

Структура, содержащая следующие целочисленные поля:

- `offset` -- Смещение секции оверлея. Равно 0 для PE-файлов, не имеющих данных оверлея, и не определено для файлов, не являющихся PE.
- `size` -- Размер секции оверлея. Равен 0 для PE-файлов, не имеющих данных оверлея, и не определён для файлов, не являющихся PE.

*Пример: uint8(pe.overlay.offset) == 0x0d and pe.overlay.size > 1024*

### number_of_resources

Количество ресурсов в PE.

### resource_timestamp

Временная метка ресурсов. Хранится как целое число.

### resource_version

Объект с двумя целочисленными атрибутами -- основная и дополнительная версии.

- `major` -- Основная версия ресурсов.
- `minor` -- Дополнительная версия ресурсов.

### resources

*Изменено в версии 3.3.0*

Массив объектов ресурсов с нумерацией от нуля, по одному для каждого ресурса PE. Доступ к отдельным ресурсам осуществляется с помощью оператора `[]`. Каждый объект ресурса имеет следующие атрибуты:

- `rva` -- RVA данных ресурса.
- `offset` -- Смещение данных ресурса. Может быть не определено, если RVA недействителен.
- `length` -- Длина данных ресурса.
- `type` -- Тип ресурса (целое число).
- `id` -- Идентификатор ресурса (целое число).
- `language` -- Язык ресурса (целое число).
- `type_string` -- Тип ресурса в виде строки, если указан.
- `name_string` -- Имя ресурса в виде строки, если указано.
- `language_string` -- Язык ресурса в виде строки, если указан.

Все ресурсы должны иметь указанные тип, идентификатор (имя) и язык. Они могут быть либо целым числом, либо строкой, но не обоими одновременно для любого данного уровня.

*Пример: pe.resources[0].type == pe.RESOURCE_TYPE_RCDATA*

*Пример: pe.resources[0].name_string == "F\\x00I\\x00L\\x00E\\x00"*

Типы ресурсов можно проверять с помощью следующих констант:

- `RESOURCE_TYPE_CURSOR`
- `RESOURCE_TYPE_BITMAP`
- `RESOURCE_TYPE_ICON`
- `RESOURCE_TYPE_MENU`
- `RESOURCE_TYPE_DIALOG`
- `RESOURCE_TYPE_STRING`
- `RESOURCE_TYPE_FONTDIR`
- `RESOURCE_TYPE_FONT`
- `RESOURCE_TYPE_ACCELERATOR`
- `RESOURCE_TYPE_RCDATA`
- `RESOURCE_TYPE_MESSAGETABLE`
- `RESOURCE_TYPE_GROUP_CURSOR`
- `RESOURCE_TYPE_GROUP_ICON`
- `RESOURCE_TYPE_VERSION`
- `RESOURCE_TYPE_DLGINCLUDE`
- `RESOURCE_TYPE_PLUGPLAY`
- `RESOURCE_TYPE_VXD`
- `RESOURCE_TYPE_ANICURSOR`
- `RESOURCE_TYPE_ANIICON`
- `RESOURCE_TYPE_HTML`
- `RESOURCE_TYPE_MANIFEST`

Для получения дополнительной информации обратитесь к:

http://msdn.microsoft.com/en-us/library/ms648009(v=vs.85).aspx

### version_info

*Добавлено в версии 3.2.0*

Словарь, содержащий информацию о версии PE. Типичные ключи:

- `Comments`
- `CompanyName`
- `FileDescription`
- `FileVersion`
- `InternalName`
- `LegalCopyright`
- `LegalTrademarks`
- `OriginalFilename`
- `ProductName`
- `ProductVersion`

Для получения дополнительной информации обратитесь к:

http://msdn.microsoft.com/en-us/library/windows/desktop/ms646987(v=vs.85).aspx

*Пример: pe.version_info["CompanyName"] contains "Microsoft"*

### version_info_list

Массив структур, содержащих информацию о версии PE.

- `key` -- Ключ информации о версии.
- `value` -- Значение информации о версии.

*Пример: pe.version_info_list[0].value contains "Microsoft"*

### number_of_signatures

Количество подписей Authenticode в PE.

### is_signed

Истина, если какая-либо из подписей PE верифицирована. Верификация здесь означает, что подпись формально корректна: дайджесты совпадают, открытый ключ подписанта корректно верифицирует зашифрованный дайджест и т.д. Однако это не означает, что подписанту (и, следовательно, подписи) можно доверять, поскольку при верификации не используются якоря доверия.

### signatures

Массив объектов подписей с нумерацией от нуля, по одному для каждой подписи Authenticode в PE-файле. Обычно PE-файлы имеют одну подпись.

- `thumbprint` -- *(Добавлено в версии 3.8.0)* Строка, содержащая отпечаток подписи.

- `issuer` -- Строка, содержащая информацию об издателе. Вот несколько примеров:

  ```
  "/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Code Signing PCA"

  "/C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=Terms of use at https://www.verisign.com/rpa (c)10/CN=VeriSign Class 3 Code Signing 2010 CA"

  "/C=GB/ST=Greater Manchester/L=Salford/O=COMODO CA Limited/CN=COMODO Code Signing CA 2"
  ```

- `subject` -- Строка, содержащая информацию о субъекте.

- `version` -- Номер версии.

- `algorithm` -- Строковое представление алгоритма, используемого для данной подписи. Обычно "sha1WithRSAEncryption". Это зависит от реализации и, возможно, версий X.509 и PKCS#7; рассмотрите использование `algorithm_oid` вместо этого.

- `algorithm_oid` -- Идентификатор объекта алгоритма, используемого для данной подписи, выраженный в числовой точечной нотации ASN.1. Имя, содержащееся в `algorithm`, выводится из этого значения. Ожидается, что идентификатор объекта будет стабильным для различных реализаций и версий X.509 и PKCS#7.

  Например, при использовании текущей реализации на основе OpenSSL:

  ```
  algorithm_oid == "1.2.840.113549.1.1.11"
  ```

  функционально эквивалентно:

  ```
  algorithm == "sha1WithRSAEncryption"
  ```

- `serial` -- Строка, содержащая серийный номер. Пример:

  ```
  "52:00:e5:aa:25:56:fc:1a:86:ed:96:c9:d4:4b:33:c7"
  ```

- `not_before` -- Метка времени Unix, с которой начинается период действия данной подписи.

- `not_after` -- Метка времени Unix, на которой заканчивается период действия данной подписи.

- `valid_on(timestamp)` -- Функция, возвращающая истину, если подпись была действительна на дату, указанную в *timestamp*. Следующее выражение:

  ```
  pe.signatures[n].valid_on(timestamp)
  ```

  Эквивалентно:

  ```
  timestamp >= pe.signatures[n].not_before and timestamp <= pe.signatures[n].not_after
  ```

- `verified` -- Логическое значение, истина, если подпись успешно верифицирована. Более подробная информация о значении `verified` описана в атрибуте `pe.is_signed`.

- `digest_alg` -- Имя алгоритма, используемого для дайджеста файла. Обычно "sha1" или "sha256".

- `digest` -- Дайджест файла, подписанный в подписи.

- `file_digest` -- Вычисленный дайджест анализируемого файла с использованием `digest_alg`.

- `number_of_certificates` -- Количество сертификатов, хранящихся в подписи, включая сертификаты из контрподписей.

- `certificates` -- Массив сертификатов с нумерацией от нуля, хранящихся в подписи, включая сертификаты из контрподписей. Члены сертификатов идентичны описанным ранее, с теми же именами.

  - `thumbprint`
  - `issuer`
  - `subject`
  - `version`
  - `algorithm`
  - `serial`
  - `not_before`
  - `not_after`

- `signer_info` -- Информация о подписанте подписи.

  - `program_name` -- Необязательное имя программы, хранящееся в подписи.
  - `digest` -- Подписанный дайджест подписи.
  - `digest_alg` -- Алгоритм, используемый для дайджеста подписи. Обычно "sha1" или "sha256".
  - `length_of_chain` -- Количество сертификатов в цепочке подписанта.
  - `chain` -- Массив сертификатов с нумерацией от нуля в цепочке подписанта. Члены сертификатов идентичны описанным ранее, с теми же именами.
    - `thumbprint`
    - `issuer`
    - `subject`
    - `version`
    - `algorithm`
    - `serial`
    - `not_before`
    - `not_after`

- `number_of_countersignatures` -- Количество контрподписей данной подписи.

- `countersignatures` -- Массив контрподписей данной подписи с нумерацией от нуля. Почти всегда это одна временная метка.

  - `verified` -- Логическое значение, истина, если контрподпись успешно верифицирована. Более подробная информация о значении `verified` описана в атрибуте `pe.is_signed`.
  - `sign_time` -- Целое число -- время подписания временной метки в формате Unix.
  - `digest` -- Подписанный дайджест контрподписи.
  - `digest_alg` -- Алгоритм, используемый для дайджеста контрподписи. Обычно "sha1" или "sha256".
  - `length_of_chain` -- Количество сертификатов в цепочке контрподписанта.
  - `chain` -- Массив сертификатов с нумерацией от нуля в цепочке контрподписанта. Члены сертификатов идентичны описанным ранее, с теми же именами.
    - `thumbprint`
    - `issuer`
    - `subject`
    - `version`
    - `algorithm`
    - `serial`
    - `not_before`
    - `not_after`

### rich_signature

Структура, содержащая информацию о rich-подписи PE, как описано [здесь](http://www.ntcore.com/files/richsign.htm).

- `offset` -- Смещение, где начинается rich-подпись. Будет не определено, если файл не содержит rich-подписи.
- `length` -- Длина rich-подписи, не включая финальный маркер "Rich".
- `key` -- Ключ, используемый для шифрования данных с помощью XOR.
- `raw_data` -- Необработанные данные в том виде, в каком они присутствуют в файле.
- `clear_data` -- Данные после расшифровки путём применения XOR с ключом.
- `version_data` -- *(Добавлено в версии 4.3.0)* Поля версии после расшифровки путём применения XOR с ключом.

#### version(version, [toolid])

*Добавлено в версии 3.5.0*

Функция, возвращающая сумму значений count всех совпадающих записей *version*. Укажите необязательный аргумент *toolid*, чтобы совпадение происходило только когда оба значения совпадают для одной записи. Дополнительную информацию можно найти здесь:

http://www.ntcore.com/files/richsign.htm

Примечание: до версии *3.11.0* эта функция возвращала только логическое значение (0 или 1), если указанные *version* и необязательный *toolid* присутствуют в записи.

*Пример: pe.rich_signature.version(24215, 261) == 61*

#### toolid(toolid, [version])

*Добавлено в версии 3.5.0*

Функция, возвращающая сумму значений count всех совпадающих записей *toolid*. Укажите необязательный аргумент *version*, чтобы совпадение происходило только когда оба значения совпадают для одной записи. Дополнительную информацию можно найти здесь:

http://www.ntcore.com/files/richsign.htm

Примечание: до версии *3.11.0* эта функция возвращала только логическое значение (0 или 1), если указанные *toolid* и необязательный *version* присутствуют в записи.

*Пример: pe.rich_signature.toolid(170, 40219) >= 99*

### pdb_path

*Добавлено в версии 4.0.0*

Путь к PDB-файлу для данного PE, если он присутствует.

*Пример: pe.pdb_path == "D:\\workspace\\2018_R9_RelBld\\target\\checkout\\custprof\\Release\\custprof.pdb"*

### exports(function_name)

Функция, возвращающая истину, если PE экспортирует *function_name*, или ложь в противном случае.

*Пример: pe.exports("CPlApplet")*

### exports(ordinal)

*Добавлено в версии 3.6.0*

Функция, возвращающая истину, если PE экспортирует *ordinal*, или ложь в противном случае.

*Пример: pe.exports(72)*

### exports(/regular_expression/)

*Добавлено в версии 3.7.1*

Функция, возвращающая истину, если PE экспортирует имя, соответствующее *regular_expression*, или ложь в противном случае.

*Пример: pe.exports(/^AXS@@/)*

### exports_index(function_name)

*Добавлено в версии 4.0.0*

Функция, возвращающая индекс в массиве `export_details`, где находится именованная функция, или неопределённое значение в противном случае.

*Пример: pe.exports_index("CPlApplet")*

### exports_index(ordinal)

*Добавлено в версии 4.0.0*

Функция, возвращающая индекс в массиве `export_details`, где находится экспортируемый ординал, или неопределённое значение в противном случае.

*Пример: pe.exports_index(72)*

### exports_index(/regular_expression/)

*Добавлено в версии 4.0.0*

Функция, возвращающая первый индекс в массиве `export_details`, где регулярное выражение совпадает с именем экспорта, или неопределённое значение в противном случае.

*Пример: pe.exports_index(/^ERS@@/)*

### number_of_exports

*Добавлено в версии 3.6.0*

Количество экспортов в PE.

### export_details

*Добавлено в версии 4.0.0*

Массив структур, содержащих информацию об экспортах PE.

- `offset` -- Смещение, где начинается экспортируемая функция.
- `name` -- Имя экспортируемой функции. Будет не определено, если функция не имеет имени.
- `forward_name` -- Имя функции, на которую переадресуется данный экспорт. Будет не определено, если экспорт не является переадресующим.
- `ordinal` -- Ординал экспортируемой функции после применения базы ординалов.

### dll_name

*Добавлено в версии 4.0.0*

Имя DLL, если оно существует в каталоге экспорта.

### export_timestamp

*Добавлено в версии 4.0.0*

Временная метка создания данных экспорта.

### number_of_imports

*Добавлено в версии 3.6.0*

Количество импортируемых DLL в PE.

### number_of_imported_functions

*Добавлено в версии 4.1.0*

Количество импортируемых функций в PE.

### number_of_delayed_imports

*Добавлено в версии 4.2.0*

Количество DLL отложенного импорта в PE. (Количество структур IMAGE_DELAYLOAD_DESCRIPTOR, разобранных из файла)

### number_of_delay_imported_functions

*Добавлено в версии 4.2.0*

Количество функций отложенного импорта в PE.

### imports(dll_name, function_name)

Функция, возвращающая истину, если PE импортирует *function_name* из *dll_name*, или ложь в противном случае. *dll_name* нечувствителен к регистру.

*Пример: pe.imports("kernel32.dll", "WriteProcessMemory")*

### imports(dll_name)

*Добавлено в версии 3.5.0*
*Изменено в версии 4.0.0*

Функция, возвращающая количество функций из *dll_name* в импортах PE. *dll_name* нечувствителен к регистру.

Примечание: до версии 4.0.0 эта функция возвращала только логическое значение, указывающее, найдено ли указанное имя DLL в импортах PE. Это изменение обратно совместимо, поскольку любое число больше 0 также вычисляется как истина.

*Примеры: pe.imports("kernel32.dll"), pe.imports("kernel32.dll") == 10*

### imports(dll_name, ordinal)

*Добавлено в версии 3.5.0*

Функция, возвращающая истину, если PE импортирует *ordinal* из *dll_name*, или ложь в противном случае. *dll_name* нечувствителен к регистру.

*Пример: pe.imports("WS2_32.DLL", 3)*

### imports(dll_regexp, function_regexp)

*Добавлено в версии 3.8.0*
*Изменено в версии 4.0.0*

Функция, возвращающая количество функций из импортов PE, где имя функции соответствует *function_regexp*, а имя DLL соответствует *dll_regexp*. Оба выражения *dll_regexp* и *function_regexp* чувствительны к регистру, если вы не используете модификатор "/i" в регулярном выражении, как показано в примере ниже.

Примечание: до версии 4.0.0 эта функция возвращала только логическое значение, указывающее, найден ли соответствующий импорт или нет. Это изменение обратно совместимо, поскольку любое число больше 0 также вычисляется как истина.

*Пример: pe.imports(/kernel32\.dll/i, /(Read|Write)ProcessMemory/) == 2*

### imports(import_flag, dll_name, function_name)

*Добавлено в версии 4.2.0*

Функция, возвращающая истину, если PE импортирует *function_name* из *dll_name*, или ложь в противном случае. *dll_name* нечувствителен к регистру.

*import_flag* -- это флаг, определяющий тип импорта, который YARA должен искать. Это значение может быть составлено побитовым ИЛИ из следующих значений:

- `pe.IMPORT_STANDARD` -- Поиск в стандартных импортах.
- `pe.IMPORT_DELAYED` -- Поиск в отложенных импортах.
- `pe.IMPORT_ANY` -- Поиск во всех импортах.

*Пример: pe.imports(pe.IMPORT_DELAYED | pe.IMPORT_STANDARD, "kernel32.dll", "WriteProcessMemory")*

### imports(import_flag, dll_name)

*Добавлено в версии 4.2.0*

Функция, возвращающая количество функций из *dll_name* в импортах PE. *dll_name* нечувствителен к регистру.

*Примеры: pe.imports(pe.IMPORT_DELAYED, "kernel32.dll"), pe.imports("kernel32.dll") == 10*

### imports(import_flag, dll_name, ordinal)

*Добавлено в версии 4.2.0*

Функция, возвращающая истину, если PE импортирует *ordinal* из *dll_name*, или ложь в противном случае. *dll_name* нечувствителен к регистру.

*Пример: pe.imports(pe.IMPORT_DELAYED, "WS2_32.DLL", 3)*

### imports(import_flag, dll_regexp, function_regexp)

*Добавлено в версии 4.2.0*

Функция, возвращающая количество функций из импортов PE, где имя функции соответствует *function_regexp*, а имя DLL соответствует *dll_regexp*. Оба выражения *dll_regexp* и *function_regexp* чувствительны к регистру, если вы не используете модификатор "/i" в регулярном выражении, как показано в примере ниже.

*Пример: pe.imports(pe.IMPORT_DELAYED, /kernel32\.dll/i, /(Read|Write)ProcessMemory/) == 2*

### import_details

*Добавлено в версии 4.2.0*

Массив структур, содержащих информацию о библиотеках импорта PE.

- `library_name` -- Имя библиотеки.
- `number_of_functions` -- Количество импортируемых функций.
- `functions` -- Массив структур, содержащих информацию о функциях импорта PE.
  - `name` -- Имя импортируемой функции.
  - `ordinal` -- Ординал импортируемой функции. Если ординал не существует, значение равно YR_UNDEFINED.
  - `rva` -- *(Добавлено в версии 4.3.0)* Относительный виртуальный адрес (RVA) импортируемой функции. Если RVA не найден, значение равно YR_UNDEFINED.

*Пример: pe.import_details[1].library_name == "library_name"*

### delayed_import_details

*Добавлено в версии 4.2.0*

Массив структур, содержащих информацию о библиотеках отложенного импорта PE.

- `library_name` -- Имя библиотеки.
- `number_of_functions` -- Количество импортируемых функций.
- `functions` -- Массив структур, содержащих информацию о функциях импорта PE.
  - `name` -- Имя импортируемой функции.
  - `ordinal` -- Ординал импортируемой функции. Если ординал не существует, значение равно YR_UNDEFINED.
  - `rva` -- *(Добавлено в версии 4.3.0)* Относительный виртуальный адрес (RVA) импортируемой функции. Если RVA не найден, значение равно YR_UNDEFINED.

*Пример: pe.delayed_import_details[1].name == "library_name"*

### import_rva(dll, function)

*Добавлено в версии 4.3.0*

Функция, возвращающая RVA импорта, соответствующего имени DLL и имени функции.

*Пример: pe.import_rva("PtImageRW.dll", "ord4") == 254924*

### import_rva(dll, ordinal)

*Добавлено в версии 4.3.0*

Функция, возвращающая RVA импорта, соответствующего имени DLL и номеру ординала.

*Пример: pe.import_rva("PtPDF417Decode.dll", 4) == 254924*

### delayed_import_rva(dll, function)

*Добавлено в версии 4.3.0*

Функция, возвращающая RVA отложенного импорта, соответствующего имени DLL и имени функции.

*Пример: pe.delayed_import_rva("QDB.dll", "ord116") == 6110705*

### delayed_import_rva(dll, ordinal)

*Добавлено в версии 4.3.0*

Функция, возвращающая RVA отложенного импорта, соответствующего имени DLL и номеру ординала.

*Пример: pe.delayed_import_rva("QDB.dll", 116) == 6110705*

### locale(locale_identifier)

*Добавлено в версии 3.2.0*

Функция, возвращающая истину, если PE содержит ресурс с указанным идентификатором локали. Идентификаторы локали -- это 16-битные целые числа, их можно найти здесь:

http://msdn.microsoft.com/en-us/library/windows/desktop/dd318693(v=vs.85).aspx

*Пример: pe.locale(0x0419) // Русский (RU)*

### language(language_identifier)

*Добавлено в версии 3.2.0*

Функция, возвращающая истину, если PE содержит ресурс с указанным идентификатором языка. Идентификаторы языка -- это 8-битные целые числа, их можно найти здесь:

http://msdn.microsoft.com/en-us/library/windows/desktop/dd318693(v=vs.85).aspx

*Пример: pe.language(0x0A) // Испанский*

### imphash()

*Добавлено в версии 3.2.0*

Функция, возвращающая хеш импорта (imphash) для PE. Imphash -- это MD5-хеш таблицы импорта PE после некоторой нормализации. Imphash для PE также может быть вычислен с помощью [pefile](http://code.google.com/p/pefile/), и дополнительную информацию можно найти в [блоге Mandiant](https://www.mandiant.com/resources/blog/tracking-malware-import-hashing/). Возвращаемая строка хеша всегда в нижнем регистре.

*Пример: pe.imphash() == "b8bb385806b89680e13fc0cf24f4431e"*

### section_index(name)

Функция, возвращающая индекс в массиве секций для секции с именем *name*. *name* чувствителен к регистру.

*Пример: pe.section_index(".TEXT")*

### section_index(addr)

*Добавлено в версии 3.3.0*

Функция, возвращающая индекс в массиве секций для секции, содержащей *addr*. *addr* может быть смещением в файле или адресом в памяти.

*Пример: pe.section_index(pe.entry_point)*

### is_pe

*Добавлено в версии 3.8.0*

Возвращает истину, если файл является PE.

*Пример: pe.is_pe*

### is_dll()

*Добавлено в версии 3.5.0*

Функция, возвращающая истину, если PE является DLL.

*Пример: pe.is_dll()*

### is_32bit()

*Добавлено в версии 3.5.0*

Функция, возвращающая истину, если PE является 32-битным.

*Пример: pe.is_32bit()*

### is_64bit()

*Добавлено в версии 3.5.0*

Функция, возвращающая истину, если PE является 64-битным.

*Пример: pe.is_64bit()*

### rva_to_offset(addr)

*Добавлено в версии 3.6.0*

Функция, возвращающая смещение в файле для RVA *addr*. Будьте внимательны: передавайте сюда относительные адреса, а не абсолютные, такие как `pe.entry_point` при сканировании процесса.

*Пример: pe.rva_to_offset(pe.sections[0].virtual_address) == pe.sections[0].raw_data_offset*

Этот пример проверяет, что смещение для виртуального адреса первой секции равно файловому смещению этой секции.
