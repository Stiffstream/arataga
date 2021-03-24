# The description of the structure and content of user-list file

**Note.** The user-list file format was designed for automatic generation, so it may not look well suited for manual editing.

## Empty lines, commends and descriptions

The user-list file is processed line-by-line. Each line can be:

* an empty line. Doesn't contain anything except whitespace symbols;
* a comment. Comment is a line that has `#` as the first non-whitespace symbol;
* a description of a user or domain limit. If the first non-whitespace symbol is not `#` then the line is treated as a description;

For example:
Например:

```
# A comment with several empty lines below.


   # This is also a comment.
	  # # # ##### And this is a comment too.

# The next line is a description of a user.
192.168.1.1 3000 user 12345 = 0 0 3 34567
# The next line is a description of a user too.
3232235777 3003 3232235777 = 1024000 1024000 0 34568

# The next line is a description of domain limits.
3 = vk.com 5mibps 5mibps facebook.com 10mibps 8mibps youtube.com 4mib 2mib
```

Note. Comments must occupy the entire line. You can't put comments on the same line as the description. For example, here is a valid comment:

```
# There are no limits for a user.
192.168.1.1 3000 vip-client 12345 = 0 0 0 11111
```

But this is a mistake:

```
192.168.1.1 3000 vip-client 12345 = 0 0 0 11111 # There are no limits for a user.
```

because in that case `# There are no limits for a user.` is treated as a part of user description, and will lead to a parsing error.

## Description of a user

The user description is done on a single line, no hyphenation is allowed.

Users in arataga can be authenticated in two different ways. Each method requires its own user description.

If the user is authenticated by login/password, the description of the user is in the form:

```
IN_IPv4 IN_PORT LOGIN PASSWORD = BANDLIM_IN BANDLIM_OUT DOMAIN_LIM_ID ID
```

If a user is authenticated by his/her IP address, the description of this user is set in the form:

```
IN_IPv4 IN_PORT USER_IPv4 = BANDLIM_IN BANDLIM_OUT DOMAIN_LIM_ID ID
```

Где:

* `IN_IPv4` is the IPv4 address of the arataga entry point. It can be specified either as an integer decimal number or in the familiar dotted-decimal notation;
* `IN_PORT` is the TCP port of the arataga entry point. It is set as an integer decimal number;
* `LOGIN` -- username (a sequence of non-space characters);
* `PASSWORD` -- user password (a sequence of non-space characters);
* `USER_IPv4` -- This is the IPv4 address from which the user is allowed to connect to arataga without a login/password. It can be specified either as an integer decimal number or in the usual dotted-decimal notation;
* `BANDLIM_IN` -- bandwidth limit for data the user downloads from target nodes. A value of 0 indicates that there is no limit;
* `BANDLIM_OUT` -- bandwidth limit for data that the user downloads to the target nodes. A value of 0 indicates that there is no limit;
* `DOMAIN_LIM_ID` -- Domain limit description identifier. Integer decimal number. The absence of such a description is not considered an error, in this case it is assumed that no domain limits are set for the user;
* `ID` - user ID. Integer decimal number.

Examples:

```
# Entry point at 192.168.1.1:3000 with auth by login/password.
# There is no limits for the user.
192.168.1.1 3000 vip-client 12345 = 0 0 0 11111

# Entry point at 192.168.1.1:3000 with auth by login/password.
# IP-address is specified as an integer.
# There is no limits for the user.
3232235777 3000 another-client 34567 = 0 0 0 11111

# Entry point at 192.168.1.1:3003 from IP-address 192.168.1.2.
# There is no limits for the user.
3232235777 3003 3232235778 = 0 0 0 11111

# Entry point at 192.168.1.1:3003 from IP-address 192.168.1.3.
# There is no limits for the user.
192.168.1.1 3003 3232235779 = 0 0 0 11111

# Entry point at 192.168.1.1:3003 from IP-address 192.168.1.100.
# There is no limits for the user.
3232235777 3003 192.168.1.100 = 0 0 0 11111

# Entry point at 192.168.1.1:3000 with auth by login/password.
# There are limits for the user.
192.168.1.1 3000 user 12345 = 1024000 512000 0 1234567

# Entry point at 192.168.1.1:3003 from IP-address 192.168.1.100.
# There are limits for the user.
3232235777 3003 192.168.1.100 = 100kib 75kib 0 1234567

# Entry point at 192.168.1.1:3005 from IP-address 192.168.1.100.
# There is no pesonal limits for the user, but domain limits are applied.
192.168.1.1 3005 192.168.1.100 = 0 0 15 1234567

# Entry point at 192.168.1.1:3007 with auth by login/password.
# The user has personal limits, the domain limits are also applied.
192.168.1.1 3007 user 12345 = 1024000 512000 15 1234567
```

## Description of domain limits

The description of one domain limit should be done in one line, the description can't be splitted into several lines.

Every domain limits must have a unique numeric ID.

The description of one domain limit has the following format:

```
DOMAIN_LIM_ID = DOMAIN1 BANDLIM_IN1 BANDLIM_OUT1 [DOMAIN2 BANDLIM_IN2 BANDLIM_OUT2 [...]]
```

(square brackets denote optional parts that can be missed),

where:

* `DOMAIN_LIM_ID` -- a numeric ID for the limit in decimal notation;
* `DOMAIN(i)` -- the domain name for that the limits are specified;
* `BANDLIM_IN(i)` -- bandwidth limit for data that a user downloads from the domain (and its subdomains). Value 0 means that there is no download limit;
* `BANDLIM_OUT(i)` -- bandwidth limit for data that a user uploads to the domain (and its subdomains). Value 0 means that there is no upload limit.

For example:

```
# Just one domain in limits.
15 = vk.com 5mib 3mib

# Several domains in limits.
16 = vk.com 10mib 5mib facebook.com 7mib 4mib youtube.com 10mib 2mib
```

It's possible to specify a limit for a domain, and another limit for a subdomain for that domain, for example:

```
# For vk.com and all its subdomain (excepts static.vk.com) there is a limit 10/5mib.
# The limit for static.vk.com is 20/1mib.
17 = vk.com 10mib 5mib static.vk.com 20mib 1mib
```
