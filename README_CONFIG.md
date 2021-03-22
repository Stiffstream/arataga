# The desctiption of the structure and content of the config file

## Empty lines, comments and commands

The configuration file is processed line by line. Each line can be:

* an empty line, i.e. does not contain anything but whitespace characters;
* A comment. A comment is a line, where the first non-space character is a trellis `#`.
* command. A string whose first nonwhite character is different from `#` character is considered a command.

For example:
```
# A comment with several empty lines below.


   # This is also a comment.
	  # # # ##### And this is a comment too.

# The next line is a command.
log_level debug

# Yet more commands below.
bandlim.in 500kib
bandlim.out 500kib
acl.max.conn 1000
```

**Note.**The comment must occupy the entire line. You cannot put comments on the same line as the command. For example, here is a valid comment:
```
# No limits.
bandlim.in 0
```
But this is wrong:
```
bandlim.in 0 # No limits.
```
because in that case `# No limits` will be treated as a part of `bandlim.in` commands, and will cause a parsing error.

## Repeated commands

If a command is specified several times then each subsequent occurrence of the command replaces the value given by the previous occurrence. For example:

```
bandlim.in 100

bandlim.out 256kib

bandlim.in 100kib

bandlim.in 5mib
```

In that case the the result value for `bandlim.in` will be 5MiB, all the previous values will be ignored.

The only exception is `acl` command.

## An example of config file

```
# Set the log level.
log_level trace

# Set default bandwidth limits.
# Those values will be used if a user has no personal limits.
bandlim.in 700kib
bandlim.out 700kib

# Max number of parallel active connections to a single ACL.
acl.max.conn 150

# Size of I/O buffer for data transfer.
acl.io.chunk_size 4kib

# A list of denied ports. Users can't connect to those ports on target hosts.
denied_ports 25, 83, 100-110, 465, 587

# List of ACL.
acl socks, port=3010, in_ip=127.0.0.1, out_ip=192.168.100.1
acl socks, port=3011, in_ip=127.0.0.1, out_ip=192.168.100.1
```

## Config file commands

### acl

Defines a single ACL. Every occurrence of ACL command defines a new ACL.

Format:
```
acl <TYPE>, <PARAMETERS>
```
Where TYPE can have one of the following values:

* `auto`. The type of the protocol will be detected automatically;
* `socks`. ACL will serve only SOCKS5 protocol;
* `http`. ACL will serve only HTTP/1.1 protocol.

Parameters:

* `port`. TCP-port for accepting incoming connections from users;
* `in_ip`. IPv4 address for accepting incoming connections from users;
* `out_ip`. IP address to be used as the source for outgoing connections. It can be either an IPv4 or IPv6 address.

Parameters are specified in the format `name=value` and are separated by commas.

The order of parameters after TYPE isn't significant.

**Attention.** Every `acl` command should have an unique pair `in_ip` and `port`.

Example:

```
acl socks, port=8000, in_ip=127.0.0.1, out_ip=192.168.100.1
acl auto, in_ip=192.168.100.1, port=3000, out_ip=192.168.100.1
```

### acl.io.chunk_count

Specifies a number of I/O buffers to be used for data transfer between a user and the target host.

Format:
```
acl.io.chunk_count UINT
```

The value can be zero.

Note that this number of buffers is created for each connection. That is, `chunk_count` of buffers will be created to serve the connection between the client and arataga. And the same number will be created to serve the connection between arataga and the target node. In fact, during normal operation, after all connections have been established and after data transfer has started, `chunk_count*2` of I/O buffers will be used.

The default value is 4.

This command is available since version 0.2.0.

### acl.io.chunk_size

Specifies the size in bytes for I/O buffers used for data transfer between a user and the target host.

Format:
```
acl.io.chunk_size UINT[suffix]
```

where *suffix* is an optional suffix that specifies the units:

* if there is no suffix then the value is specified in bytes. For example: `acl.io.chunk_size 1024000`;
* `b`, the value is specified in bytes. It means that `acl.io.chunk_sise 20000` is the same as `acl.io.chunk_size 20000b`;
* `kib`, the value is specified in kibibytes (KiB, 1024 bytes in a kibibyte). For example, `acl.io.chunk_size 100kib` is the same as `acl.io.chunk_size 102400b`;
* `mib`, the value is specified in mebibytes (MiB, 1048576 bytes in a mebibyte, or 1024 kibibytes). For example, `acl.io.chunk_size 5MiB` is the same as `acl.io.chunk_size 5242880b`, or `acl.io.chunk_size 5120kib`;
* `gib`, the value is specified in gibitypes (GiB, 1073741824 bytes in a gibibyte, or 1024 mebibytes).

The value can't zero.

**Note:** During the process of connecting a client to an ACL, there may be several exchanges between the client and the ACL as long as the client is authenticated. During these exchanges, intermediate I/O buffers are used, the size of which is determined based on the client protocol. After the client is successfully authenticated and a connection to the remote host is established, the ACL begins to use the I/O buffers for the main data exchange. And just the size of these buffers is set by the `acl.io.chunk_size` parameter.

The larger the value of `acl.io.chunk_size`, the more efficiently large amounts of data will be transferred. But the more memory the ACL will consume as the number of simultaneous connections increases.

The default value is 8kib.

### bandlim.in

Задает ограничение на объем данных, идущих от удаленного узла к клиенту (т.е. входящие для клиента данные). Это ограничение используется если для клиента не задан персональный лимит.

Формат:
```
bandlim.in UINT[suffix]
```

где *suffix* -- это необязательный суффикс, который указывает единицы измерения:

* `b` для байт в секунду. Так, значение `bandlim.in 300000b` будет означать ограничение в 300000 байт в секунду;
* `kib` для кибибайт в секунду. Значение `bandlim.in 30kib` будет означать ограничение в 30kib или 30720 байт в секунду;
* `mib` для мебибайт в секунду. Значение `bandlim.in 2mib` будет означать ограничение в 2mib (или 2040kib или 2088960 байт) в секунду;
* `gib` для гибибайт в секунду. Значение `bandlim.in 1gib` будет означать ограничение в 1gib (или 1024mib, или 1048576kib, или 1073741824 байт) в секунду;
* `kibps` для кибибит в секунду. Так, значение `bandlim.in 300kibps` будет означать 307200 бит/сек или 38400 байт/сек;
* `mibps` для мебибит в секунду. Так, значение `bandlim.in 5mibps` будет означать 5242880 бит/сек или 655360 байт/сек;
* `gibps` для гибибит в секунду. Так, значение `bandlim.in 1gibps` будет означать 1073741824 бит/сек или 134217728 байт/сек (131072 кибибайт/сек или 128 мебибайт/сек);
* `kbps` для килобит в секунду. Значение `bandlim.in 300kpbs` будет означать 300000 бит/сек или 37500 байт/сек (~37 кибибайт/сек);
* `mpbs` для мегабит в секунду. Значение `bandlim.in 5mpbs` будет означать 5000000 бит/сек или 625000 байт/сек (~610 кибибайт/сек);
* `gpbs` для гигабит в секунду. Значение `bandlim.in 1gbps` будет означать 1000000000 бит/сек или 125000000 байт/сек (~122070 кибибайт/сек или ~119 мебибайт/сек).

Значение 0 указывает, что ограничения на объем данных от удаленного узла к клиенту нет.

По умолчанию 0. Т.е. если команда `bandlim.in` не указана, то лимита для входящих данных клиента нет.

### bandlim.out

Задает ограничение на объем данных, идущих от клиента к удаленному узлу (т.е. исходящие от клиента данные). Это ограничение используется если для клиента не задан персональный лимит.

Формат:
```
bandlim.out UINT[suffix]
```

где *suffix* -- это необязательный суффикс, который указывает единицы измерения (см. описание `bandlim.in`).

Значение 0 указывает, что ограничения на объем данных от клиента к удаленному узлу нет.

По умолчанию 0. Т.е. если команда `bandlim.out` не указана, то лимита для исходящих данных клиента нет.

### denied_ports

Задает перечень портов, доступ к которым на целевых узлах для клиентов запрещен.

В перечне могут указываться как отдельные номера, так и диапазоны. Все значения должны быть отделены друг от друга запятыми.

Например:
```
denied_ports 25, 83, 100-110, 465, 587
```

По умолчанию этот список пуст.

### dns_cache_cleanup_period

Задает период очистки кэша с результатами поиска в DNS от старых результатов.

Формат:
```
dns_cache_cleanup_period UINT[suffix]
```

где необязательный *suffix* означает единицы измерения, в которых задано значение: `ms`, `s` или `min`. Если *suffix* не указан, то единицей измерения являются секунды.

По умолчанию 30s.

### http.limits.field_name

Задает ограничение на максимальную длину имени HTTP-заголовка.

Если при обработке HTTP-запроса или HTTP-ответа arataga обнаруживает HTTP-заголовок с именем, чья длина больше заданной в `http.limits.field_name`, то обработка такого HTTP-запроса/ответа прекращается.

Формат:
```
http.limits.field_name UINT[suffix]
```

где необязательный *suffix* означает единицы измерения, в которых задано значение: `b`, `kib`, `mib` или `gib`. Если *suffix* не указан, то единицей измерения являются байты.

По умолчанию 2KiB.

### http.limits.field_value

Задает ограничение на максимальную длину значения HTTP-заголовка.

Если при обработке HTTP-запроса или HTTP-ответа arataga обнаруживает HTTP-заголовок со значением, чья длина больше заданной в `http.limits.field_value`, то обработка такого HTTP-запроса/ответа прекращается.

Формат:
```
http.limits.field_value UINT[suffix]
```

где необязательный *suffix* означает единицы измерения, в которых задано значение: `b`, `kib`, `mib` или `gib`. Если *suffix* не указан, то единицей измерения являются байты.

По умолчанию 10KiB.

### http.limits.request_target

Задает ограничение на максимальную длину значения request-target в стартовой строке HTTP-запроса.

Если при обработке входящего HTTP-запроса arataga обнаруживает request-target со значением, чья длина больше заданной в `http.limits.request_target`, то обработка такого HTTP-запроса прекращается.

Формат:
```
http.limits.request_target UINT[suffix]
```

где необязательный *suffix* означает единицы измерения, в которых задано значение: `b`, `kib`, `mib` или `gib`. Если *suffix* не указан, то единицей измерения являются байты.

По умолчанию 8KiB.

### http.limits.status_line

Задает ограничение на максимальную длину status-line в HTTP-ответе.

Если при обработке HTTP-ответа arataga обнаруживает status-line, чья длина больше заданной в `http.limits.status_line`, то обработка такого HTTP-ответа прекращается.

Формат:
```
http.limits.status_line UINT[suffix]
```

где необязательный *suffix* означает единицы измерения, в которых задано значение: `b`, `kib`, `mib` или `gib`. Если *suffix* не указан, то единицей измерения являются байты.

По умолчанию 1KiB.

### http.limits.total_headers_size

Задает ограничение на общий суммарный размер всех HTTP-заголовков в HTTP-запросе или HTTP-ответе.

Если при обработке HTTP-запроса или HTTP-ответа arataga обнаруживает, что общая длина HTTP-заголовков больше заданной в `http.limits.total_headers_size`, то обработка такого HTTP-запроса/ответа прекращается.

Формат:
```
http.limits.total_headers_size UINT[suffix]
```

где необязательный *suffix* означает единицы измерения, в которых задано значение: `b`, `kib`, `mib` или `gib`. Если *suffix* не указан, то единицей измерения являются байты.

По умолчанию 80KiB.

### log_level

Задает уровень логирования.

Сообщения, чей уровень важности совпадает или выше, чем указанный в команде, попадают в журнал. Сообщения с уровнем важности ниже, чем указанный в команде, игнорируются и в журнале не сохраняются.

Формат:
```
log_level <LEVEL>
```
где LEVEL -- это: `trace`, `debug`, `info`, `warn`, `error`, `crit`.

Специальное значение `off` отключает логирование.

По умолчанию используется значение, которое задается в командной строке.

Если команда `log_level` в конфиге задана, то ее значение перекрывает заданное в командной строке значение.

### acl.max.conn

Ограничение на количество одновременно принятых подключений для одного ACL.

Формат:
```
acl.max.conn UINT
```

Когда количество одновременно принятых подключений достигает заданного в `acl.max.conn` значения, прием новых подключений на этот ACL приостанавливается до тех пор, пока количество подключений не упадет ниже заданного в `acl.max.conn` порога.

Значение не может быть нулевым.

По умолчанию 100.

### timeout.authentification

Задает максимальное время ожидания результата аутентификации.

Если ответ на указанное в `timeout.authentification` время не поступил, то клиент считается не аутентифицированным и ему отказывают в подключении.

Формат:
```
timeout.authentification UINT[suffix]
```

где необязательный *suffix* означает единицы измерения, в которых задано значение: `ms`, `s` или `min`. Если *suffix* не указан, то единицей измерения являются секунды.

Если суффикс задан, то он должен быть записан строчными буквами (в нижнем регистре). Например: 1200ms, 15s и т.д.

По умолчанию 1500ms.

### timeout.connect_target

Задает максимальное время ожидания результата подключения к целевому узлу.

Если за время `timeout.connect_target` подключиться к целевому узлу не удалось, то клиенту отсылается отрицательный результат.

Формат:
```
timeout.connect_target UINT[suffix]
```

где необязательный *suffix* означает единицы измерения, в которых задано значение: `ms`, `s` или `min`. Если *suffix* не указан, то единицей измерения являются секунды.

Если суффикс задан, то он должен быть записан строчными буквами (в нижнем регистре). Например: 1200ms, 15s и т.д.

По умолчанию 5s.

### timeout.dns_resolving

Задает максимальное время ожидания результата поиска IP-адреса целевого узла.

Если за время `timeout.dns_resolving` определить IP-адрес по доменному имени не удалось, то клиенту отсылается отрицательный результат.

Формат:
```
timeout.dns_resolving UINT[suffix]
```

где необязательный *suffix* означает единицы измерения, в которых задано значение: `ms`, `s` или `min`. Если *suffix* не указан, то единицей измерения являются секунды.

Если суффикс задан, то он должен быть записан строчными буквами (в нижнем регистре). Например: 1200ms, 15s и т.д.

По умолчанию 4s.

### timeout.failed_auth_reply

Задает время задержки перед отсылкой отрицательного результата аутентификации.

Если клиента аутентифицировать не удалось, то отрицательный результат может отсылаться клиенту не сразу, а по истечению заданного времени (чтобы воспрепятствовать, например, попыткам простого перебора пароля). Размер этой паузы задается командой `timeout.failed_auth_reply`.

Формат:
```
timeout.dns_resolving UINT[suffix]
```

где необязательный *suffix* означает единицы измерения, в которых задано значение: `ms`, `s` или `min`. Если *suffix* не указан, то единицей измерения являются секунды.

Если суффикс задан, то он должен быть записан строчными буквами (в нижнем регистре). Например: 1200ms, 15s и т.д.

По умолчанию 750ms.

### timeout.http.headers_complete

Задает максимальное время ожидания завершения чтения всех заголовков входящего HTTP-запроса от клиента.

Если за отведенное время все заголовки прочитаны не были (например, клиент перестал отсылать данные со своей стороны или же шлет их с очень маленькой скоростью), то клиенту отсылается ответ 408 Request Timeout и входящее соединение закрывается.

Формат:
```
timeout.http.headers_complete UINT[suffix]
```

где необязательный *suffix* означает единицы измерения, в которых задано значение: `ms`, `s` или `min`. Если *suffix* не указан, то единицей измерения являются секунды.

Если суффикс задан, то он должен быть записан строчными буквами (в нижнем регистре). Например: 1200ms, 15s и т.д.

По умолчанию 5s.

### timeout.http.negative_response

Задает максимальное время записи отрицательного ответа клиенту.

Если клиент прислал запрос, который не представляется возможным обработать, то клиенту отсылается отрицательный ответ. На время записи этого ответа накладывается ограничение. Если за отведенное время ответ не был записан (например, клиент со своей стороны перестал читать данные), то соединение принудительно закрывается.

Формат:
```
timeout.http.negative_response UINT[suffix]
```

где необязательный *suffix* означает единицы измерения, в которых задано значение: `ms`, `s` или `min`. Если *suffix* не указан, то единицей измерения являются секунды.

Если суффикс задан, то он должен быть записан строчными буквами (в нижнем регистре). Например: 1200ms, 15s и т.д.

По умолчанию 2s.

### timeout.idle_connection

Задает максимальное время жизни для соединений, в которых нет активности.

Если за время, указанное в `timeout.idle_connection`, не было входящих данных ни с одной из сторон, то соединение принудительно закрывается.

Формат:
```
timeout.idle_connection UINT[suffix]
```

где необязательный *suffix* означает единицы измерения, в которых задано значение: `ms`, `s` или `min`. Если *suffix* не указан, то единицей измерения являются секунды.

Если суффикс задан, то он должен быть записан строчными буквами (в нижнем регистре). Например: 1200ms, 15s и т.д.

По умолчанию 5min.

### timeout.protocol_detection

Задает максимальное время в течении которого ACL должен определить, какой протокол будет использовать клиент.

Если за указанное в `timeout.protocol_detection` время клиент не прислал достаточного количества байт, чтобы определить протокол общения, то соединение принудительно закрывается.

Данное значение защищает от ситуаций, когда клиент подключился и не присылает никаких данных. Или присылает их с очень медленной скоростью (например, по 1 байту в минуту).

Формат:
```
timeout.protocol_detection UINT[suffix]
```

где необязательный *suffix* означает единицы измерения, в которых задано значение: `ms`, `s` или `min`. Если *suffix* не указан, то единицей измерения являются секунды.

Если суффикс задан, то он должен быть записан строчными буквами (в нижнем регистре). Например: 1200ms, 15s и т.д.

По умолчанию 3s.

### timeout.socks.bind

Задает максимальное время, в течении которого должно быть установлено соединение с двух сторон при выполнении команды SOCKS BIND.

При выполнении команды SOCKS BIND на строне ACL открывается новый серверный сокет, адрес которого возвращается клиенту. Со стороны целевого узла на этот серверный сокет должно быть сделано новое подключение. После этого команда SOCKS BIND может считаться выполненной, и клиент может производить обмен данными с удаленным узлом.

Если за указанное в `timeout.socks.bind` время со стороны целевого узла новое подключение сделано не было, то клиенту отсылается отрицательный результат команды SOCKS BIND. И соединение с клиентом принудительно закрывается.

Формат:
```
timeout.socks.bind UINT[suffix]
```

где необязательный *suffix* означает единицы измерения, в которых задано значение: `ms`, `s` или `min`. Если *suffix* не указан, то единицей измерения являются секунды.

Если суффикс задан, то он должен быть записан строчными буквами (в нижнем регистре). Например: 1200ms, 15s и т.д.

По умолчанию 20s.

### timeout.socks.handshake

Задает максимальное время, в течении которого клиент должен завершить процедуру подключения по протоколу SOCKS5. Т.е. должен прислать метод аутентификации, затем пройти аутентификацию и прислать команду CONNECT (или BIND).

Если за указанное в `timeout.socks.handshake` время клиент не прислал достаточного количества байт для установки нормального SOCKS-подключения, то соединение принудительно закрывается.

Данное значение защищает от ситуаций, когда клиент подключился присылает данные с очень медленной скоростью (например, по 1 байту в секунду).

Формат:
```
timeout.socks.handshake UINT[suffix]
```

где необязательный *suffix* означает единицы измерения, в которых задано значение: `ms`, `s` или `min`. Если *suffix* не указан, то единицей измерения являются секунды.

Если суффикс задан, то он должен быть записан строчными буквами (в нижнем регистре). Например: 1200ms, 15s и т.д.

По умолчанию 5s.

