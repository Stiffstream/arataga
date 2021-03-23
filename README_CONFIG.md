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

The value can't be zero.

**Note:** During the process of connecting a client to an ACL, there may be several exchanges between the client and the ACL as long as the client is authenticated. During these exchanges, intermediate I/O buffers are used, the size of which is determined based on the client protocol. After the client is successfully authenticated and a connection to the remote host is established, the ACL begins to use the I/O buffers for the main data exchange. And just the size of these buffers is set by the `acl.io.chunk_size` parameter.

The larger the value of `acl.io.chunk_size`, the more efficiently large amounts of data will be transferred. But the more memory the ACL will consume as the number of simultaneous connections increases.

The default value is 8kib.

### bandlim.in

Specifies the bandwidth limit for data from the target host to a user (incoming data for the user). That limit is used if a user hasn't the personal limit for incoming data.

Format:
```
bandlim.in UINT[suffix]
```

where *suffix* is an optional suffix that specifies the units:

* `b` for bytes per second. Thus, value `bandlim.in 300000b` means the limit 300000 bytes per second;
* `kib` for kibibytes per second. Value `bandlim.in 30kib` means the limit 30kib or 30720 bytes per second;
* `mib` for mebibytes per second. Value `bandlim.in 2mib` means the limit 2mib (or 2040kib or 2088960 bytes) per second;
* `gib` for gibibytes per second. Value `bandlim.in 1gib` means the limit 1gib (or 1024mib, or 1048576kib, or 1073741824 bytes) per second;
* `kibps` for kibibits per second. Thus, value `bandlim.in 300kibps` means 307200 bits/sec or 38400 bytes/sec;
* `mibps` for mebibits per second. Thus, value `bandlim.in 5mibps` means 5242880 bits/sec or 655360 bytes/sec;
* `gibps` for gibibits per second. Thus, value `bandlim.in 1gibps` means 1073741824 bits/sec or 134217728 bytes/sec (131072 kibibytes/sec or 128 mebibytes/sec);
* `kbps` for kilobits per second. Value `bandlim.in 300kpbs` means 300000 bits/sec or 37500 bytes/sec (~37 kibibytes/sec);
* `mpbs` for megabits per second. Value `bandlim.in 5mpbs` means 5000000 bits/sec or 625000 bytes/sec (~610 kibibytes/sec);
* `gpbs` for gigabits per second. Value `bandlim.in 1gbps` means 1000000000 bits/sec or 125000000 bytes/sec (~122070 kibibytes/sec or ~119 mebibytes/sec).

Value 0 means that there is no bandwidth limit for incoming data for a user.

Default value 0. It means that if `bandlim.in` isn't specified then there is no bandwidth limit for incoming data for a user.

### bandlim.out

Specifies the bandwidth limit for data from a user to the target host (outgoing data from the user). That limit is used if a user hasn't the personal limit for outgoing data.

Format:
```
bandlim.out UINT[suffix]
```

where *suffix* is an optional suffix that specifies units (see the description of `bandlim.in` command for more details).

Value 0 means that there is no bandwidth limit for outgoing data from a user.

Default value 0. It means that if `bandlim.in` isn't specified then there is no bandwidth limit for outgoing data from a user.

### denied_ports

Specifies a list of denied ports. Users can't connect to those ports on remote hosts.

The list can contain separate port numbers and ranges. All values must be separated by commas.

For example:
```
denied_ports 25, 83, 100-110, 465, 587
```

This list is empty by default.

### dns_cache_cleanup_period

Specifies the period of cleaning the cache with DNS lookup results.

Format:
```
dns_cache_cleanup_period UINT[suffix]
```

where *suffix* is an optional suffix that specifies units: `ms`, `s` or `min`. If *suffix* isn't present then the value is treated as being specified in seconds.

Default value: 30s.

### http.limits.field_name

Specifies the max allowed length of HTTP header field name.

If arataga detects a HTTP header field that name is longer than the value of `http.limits.field_name` then the processing of such HTTP request/response will be cancelled.

Format:
```
http.limits.field_name UINT[suffix]
```

where optional *suffix* specifies units: `b`, `kib`, `mib` or `gib`. If *suffix* isn't present then the value is treated as being specified in bytes.

Default value: 2KiB.

### http.limits.field_value

Specifies the max allowed length of HTTP header field value.

If arataga detects a HTTP header field that value is longer than the value of `http.limits.field_value` then the processing of such HTTP request/response will be cancelled.

Format:
```
http.limits.field_value UINT[suffix]
```

where optional *suffix* specifies units: `b`, `kib`, `mib` or `gib`. If *suffix* isn't present then the value is treated as being specified in bytes.

Default value: 10KiB.

### http.limits.request_target

Specifies the max allowed length of request-target in the start line of an incoming HTTP request.

If arataga detects a request-target that value is longer than the value of `http.limits.request_target` then the processing of such HTTP request will be cancelled.

Format:
```
http.limits.request_target UINT[suffix]
```

where optional *suffix* specifies units: `b`, `kib`, `mib` or `gib`. If *suffix* isn't present then the value is treated as being specified in bytes.

Default value: 8KiB.

### http.limits.status_line

Specifies the max allowed length of status-line in an incoming HTTP response.

If arataga detects a status-line that value is longer than the value of `http.limits.status_line` then the processing of such HTTP response will be cancelled.

Format:
```
http.limits.status_line UINT[suffix]
```

where optional *suffix* specifies units: `b`, `kib`, `mib` or `gib`. If *suffix* isn't present then the value is treated as being specified in bytes.

Default value: 1KiB.

### http.limits.total_headers_size

Specifies the max allowed total size of all HTTP header fields.

If arataga detects that the total size of all HTTP header fields is greater than the value of `http.limits.total_headers_size` then the processing of such HTTP request/response will be cancelled.

Format:
```
http.limits.total_headers_size UINT[suffix]
```

where optional *suffix* specifies units: `b`, `kib`, `mib` or `gib`. If *suffix* isn't present then the value is treated as being specified in bytes.

Default value: 80KiB.

### log_level

Specifies the minimal severity level for messages to be stored in log.

Log messages with that level or a more highest level will be stored in log,
 all other messages will be ignored.

Format:
```
log_level <LEVEL>
```

where LEVEL can be `trace`, `debug`, `info`, `warn`, `error`, `crit`.

Special value `off` turns the logging off.

By default the value for arataga's command line is used.

If `log_level` is set in the config then its value overrides the value from the command line.

### acl.max.conn

Specifies the max number of active parallel connections for one ACL.

Format:
```
acl.max.conn UINT
```

When the number of simultaneously accepted connections reaches the value set in `acl.max.conn`, accepting new connections to this ACL is paused until the number of connections drops below the threshold set in `acl.max.conn`.

The value can't be zero.

The default value is 100.

### timeout.authentification

Specifies the maximum time to wait for an authentication result.

If no response is received to the time specified in `timeout.authentification`, the client is considered unauthenticated and will be disconnected.

Format:
```
timeout.authentification UINT[suffix]
```

where the optional *suffix* denotes the unit of measure in which the value is specified: `ms`, ``s` or `min`. If *suffix* is not specified, the unit is seconds.

If the suffix is specified, it must be written in lowercase letters. For example: 1200ms, 15s, etc.

The default is 1500ms.

### timeout.connect_target

Specifies the maximum time to wait for the result of connection to the target host.

If the `timeout.connect_target` timeout fails to connect to the target host, a negative result is sent to the client.

Format:
```
timeout.connect_target UINT[suffix]
```

where the optional *suffix* denotes the unit of measure in which the value is specified: `ms`, ``s` or `min`. If *suffix* is not specified, the unit is seconds.

If the suffix is specified, it must be written in lowercase letters. For example: 1200ms, 15s, etc.

The default is 5s.

### timeout.dns_resolving

Sets the maximum time to wait for the result of a DNS lookup for the target host.

If during `timeout.dns_resolving` the IP address could not be found by the domain name, a negative result is sent to the user.

Format:
```
timeout.dns_resolving UINT[suffix]
```

where the optional *suffix* denotes the unit of measure in which the value is specified: `ms`, ``s` or `min`. If *suffix* is not specified, the unit is seconds.

If the suffix is specified, it must be written in lowercase letters. For example: 1200ms, 15s, etc.

The default is 4s.

### timeout.failed_auth_reply

Specifies the delay time before sending a negative authentication result.

If the client failed to authenticate, the negative result can be sent to the client not immediately, but after a specified time (to prevent, for example, simple password brute-forcing attempts). The size of this pause is set with the `timeout.failed_auth_reply` command.

Format:
```
timeout.dns_resolving UINT[suffix]
```

where the optional *suffix* denotes the unit of measure in which the value is specified: `ms`, ``s` or `min`. If *suffix* is not specified, the unit is seconds.

If the suffix is specified, it must be written in lowercase letters. For example: 1200ms, 15s, etc.

The default is 750ms.

### timeout.http.headers_complete

Specifies the maximum time to wait for the client to finish reading all headers of an incoming HTTP request.

If all headers were not read within the allotted time (for example, the client stopped sending data from its side or sends it at a very low speed), the client is sent a 408 Request Timeout response and the incoming connection is closed.

Format:
```
timeout.http.headers_complete UINT[suffix]
```

where the optional *suffix* denotes the unit of measure in which the value is specified: `ms`, ``s` or `min`. If *suffix* is not specified, the unit is seconds.

If the suffix is specified, it must be written in lowercase letters. For example: 1200ms, 15s, etc.

The default is 5s.

### timeout.http.negative_response

Specifies the maximum time to send a negative response to a user.

If a user sent a request that cannot be processed, a negative response is sent to the user. A limit is imposed on the sending time of this response. If the response was not sent within the allotted time (for example, the user stopped reading the data), the connection is forcibly closed.

Format:
```
timeout.http.negative_response UINT[suffix]
```

where the optional *suffix* denotes the unit of measure in which the value is specified: `ms`, ``s` or `min`. If *suffix* is not specified, the unit is seconds.

If the suffix is specified, it must be written in lowercase letters. For example: 1200ms, 15s, etc.

The default is 2s.

### timeout.idle_connection

Specifies the maximum idle time for connections with no activity.

If there is no incoming data from either side during the time specified in `timeout.idle_connection`, the connection is forcibly closed.

Format:
```
timeout.idle_connection UINT[suffix]
```

where the optional *suffix* denotes the unit of measure in which the value is specified: `ms`, ``s` or `min`. If *suffix* is not specified, the unit is seconds.

If the suffix is specified, it must be written in lowercase letters. For example: 1200ms, 15s, etc.

The default is 5min.

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

