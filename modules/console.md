# Модуль Console

*Добавлен в версии 4.2.0*

Модуль Console позволяет выводить информацию в журнал во время выполнения условий. По умолчанию сообщения журнала отправляются в stdout, но их можно обрабатывать иначе с помощью C API (см. [Сканирование данных](../capi.md)).

Каждая функция модуля console возвращает true для целей вычисления условий. Это означает, что вы должны объединять свои выражения с помощью логического AND для получения правильного результата. Например:

```yara
import "console"

rule example
{
    condition:
        console.log("Hello") and console.log("World!")
}
```

## Справочник

### log(string)

Функция, отправляющая строку в основной callback.

*Пример: console.log(pe.imphash())*

### log(message, string)

Функция, отправляющая сообщение и строку в основной callback.

*Пример: console.log("The imphash is: ", pe.imphash())*

### log(integer)

Функция, отправляющая целое число в основной callback.

*Пример: console.log(uint32(0))*

### log(message, integer)

Функция, отправляющая сообщение и целое число в основной callback.

*Пример: console.log("32bits at 0: ", uint32(0))*

### log(float)

Функция, отправляющая число с плавающей точкой в основной callback.

*Пример: console.log(math.entropy(0, filesize))*

### log(message, float)

Функция, отправляющая сообщение и число с плавающей точкой в основной callback.

*Пример: console.log("Entropy: ", math.entropy(0, filesize))*

### hex(integer)

Функция, отправляющая целое число в основной callback в шестнадцатеричном формате.

*Пример: console.hex(uint32(0))*

### hex(message, integer)

Функция, отправляющая сообщение и целое число в шестнадцатеричном формате в основной callback.

*Пример: console.hex("Hex at 0: ", uint32(0))*
