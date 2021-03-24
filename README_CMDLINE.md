# arataga's command line arguments

## --admin-http-ip

`--admin-http-ip=[char-seq]`

**Mandatory argument.**

Specifies the IP address at which the administrative HTTP-entry for arataga management should be opened.

Can contain an IP address (such as 127.0.0.1 or 192.168.1.1) or a domain name (such as `localhost`).

## --admin-http-port

`--admin-http-port=[ushort]`

**Mandatory argument.**

Specifies the TCP-port at which the administrative HTTP-entry for arataga management should be opened.

## --admin-token

`--admin-token=[char-seq]`

**Mandatory argument.**

Sets the value for the `Arataga-Admin-Token` HTTP header field.

The `Arataga-Admin-Token` header must be present in all HTTP requests, that
come to the administrative HTTP input. The value of this header is specified on
the command line. If the value specified on the command line does not match
what is received in the HTTP request, the HTTP request is rejected.

Example:

`--admin-token=Our-Bigest-Secret-Word-Is-Abracadabra`

## --io-threads

`--io-threads=[uint]`

*Optional argument*

Sets the number of worker threads to perform network I/O.

arataga creates multiple worker threads at its startup and then serves all ACLs described in the configuration only in the context of those worker threads. Thus, if the configuration specifies 1000 ACLs, and arataga created only 4 I/O worker threads, each of those threads will serve 250 ACLs (arataga tries to distribute ACLs evenly among the worker threads).

If the `io-threads` argument is not given on the command line, then arataga calculates the number of I/O threads by itself: `nCPU-2` or 2 if nCPU is less than or equal to 2. Where `nCPU` is the number of available cores. So, if arataga is running on a single-core processor, 2 working threads will be created. If it is running on a 4-core with hyperthreading then 6 threads will be created (nCPU will be 8 in this case).

But sometimes it may be necessary to limit the number of worker threads for arataga. For example, if the ACL is only 4 and arataga is running on a 16-core processor. In this case, the number of worker threads for I/O operations is specified by the `io-threads` argument. So, if you specify `--io-threads 2`, then arataga will use only two worker threads even on a 16-core processor.

## -l, --log-level

`-l[level]` or `--log-level=[level]`

*Optional argument.*

Sets the minimum level of importance for log messages to be logged.

For example, if the level `info` is set, then messages with the levels `trace` and `debug` will not be logged.

Allowed values: `trace`, `debug`, `info`, `warn`, `error`, `crit`.

The special value `off` disables logging.

Default: `trace`.

**Note.** The value set in the command line is valid only until the configuration is read (from a local copy or when the configuration is received through the administrative HTTP input). If the `log_level` command is specified in the configuration, the minimum logging level is set equal to the value of the `log_level` command from the config.

## --local-config-path

`--local-config-path=[path]`

**Mandatory argument.**

Sets the name of the directory where arataga will save local copies of the config and user list obtained through the administrative HTTP login.

This directory must exist.

The user on whose behalf arataga is run must have permissions to create/delete/read/write files in this directory.

The value can be either an absolute directory name or a relative name (relative to the directory from which arataga is run).

Example:

`--local-config-path=/usr/etc/arataga/local-configs`

## --log-file-count

`--log-file-count=[non-zero-value]`

*Optional argument.*

If log files are used for logging, this parameter sets the maximum number of log files in rotation. So, if set to 5, no more than 5 log files will be created. After that, the new log files will overwrite the old ones.

For example, if set:

`--log-target=/var/log/arataga --log-file-count=3`

then the files `arataga`, `arataga.1`, `arataga.2`, `arataga.3` will be created in `/var/log` while arataga is running. Then the file `arataga.3` will be deleted, the file `arataga.2` will be renamed to `arataga.3`, the file `arataga.1` to `arataga.2`, and `arataga` to `arataga.1`.

This parameter must have a value of 2 or more.

The default is 3.

## --log-file-size

`--log-file-size=[bytes]`

*Optional argument.*

If log files are used for logging, then when the current log file reaches the size specified by this parameter, it is switched to another log file (log rotation is performed).

Default: 10MiB.

## --log-target

`--log-target=[name...]`

*Optional argument.*

Specifies where the log messages will go.

Can be specified more than once. Each occurrence of the `--log-target` argument must specify a different type of destination:

* console. Allowed values: `stdout`, `stderr`;
* syslog. Defined in the format `@stream-name`, where `stream-name` is the name of the syslog stream for messages;
* file name.

Examples:

* logging to the syslog only (into `arataga` stream): `arataga --log-target=@arataga`;
* logging to the standard error stread only: `arataga --log-target=stderr`;
* logging to the standard output stream, and to the syslog (into `arataga` stream): `arataga --log-target=stdout --log-target=@arataga`;
* logging to the syslog (into `arataga` stream), and to the file `/var/log/arataga.log`: `arataga --log-target=@arataga --log-target=/var/log/arataga.log`.

If not specified then the logging is performed to the stdout only.

## --max-stage-startup-time

`--max-stage-startup-time=[seconds]`

*Optional argument.*

Running arataga takes place in several stages: first it tries to load a local copy of the user list, then it tries to load a local copy of the configuration file, then it creates an HTTP administrative entry point.

Each stage must complete successfully before the next stage begins. The time that stages have to complete their work is limited. If a stage fails to start in the allotted time, arataga is forced to terminate.

The --max-stage-startup-time parameter allows you to set the maximum time allowed for the next arataga stage to complete its run.

The value is set in seconds.

The default value is 5 seconds.

## --no-daemonize

*Optional argument.*

If specified then arataga doesn't become a daemon and continue work as a usual console application.

## --setgid

`--setgid=[gid]`

*Optional argument.*

If specified, arataga makes a `setgid` system call after startup to downgrade its permissions in the system and continue working as a member of the group with the identifier given.

By default arataga does not make a `setgid` call.

## --setuid

`--setuid=[uid]`

*Optional argument.*

If specified, arataga makes a `setuid` system call after startup to downgrade its permissions in the system and continue working as a user with the identifier given.

By default arataga does not make a `setuid` call.

## --so5-combined-locks

*Optional argument.*

If specified, special implementations of mutexes inside arataga start to be used, which combine spin-locks and regular mutexes. This mode can reduce latency when processing some actions inside arataga, but at the cost of more CPU consumption.

By default, this mode is not used and regular mutexes are used inside arataga.

## -f, --log-flush-level

`-f[level]` or `--log-flush-level=[level]`

*Optional argument.*

Specifies the level of importance of messages in the log at which messages are dumped to specified destinations.

Arataga uses the [spdlog](https://github.com/gabime/spdlog) library for logging, which works in asynchronous mode (i.e. messages are not written to file/syslog immediately). Messages are periodically dumped to the file/syslog either when the internal buffers of spdlog are full or when messages of a certain severity level appear.

The `--log-flush-level' parameter sets the severity level at which the messages accumulated in the spdlog buffers will be written.

For example, if you set the level of `trace`, the recording will be done after each message (i.e. `trace` is the minimum level). If you set the `warn` level, the recording will be done only when messages with the `warn` level or higher appear.

Default: `error`.

## -h, --help

Instructs to print a help on the command line arguments and quit.

## -v, --version

Instructs to print the version number and quit.
