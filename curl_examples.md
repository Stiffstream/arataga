Some examples of running curl for debugging purposes.

# Update the config

```
curl -H "Arataga-Admin-Token: ABC" -H "Content-Type: text/plain" -X POST --data-binary @__locals/cfg/local-config.cfg http://localhost:8080/config
```

The `--data-binary` parameter is mandatory. Without it curl will remove line separators in the config file.

# Update the user-list

```
curl -H "Arataga-Admin-Token: ABC" -H "Content-Type: text/plain" -X POST --data-binary @__locals/cfg/user-list.cfg http://localhost:8080/users
```

The `--data-binary` parameter is mandatory. Without it curl will remove line separators in the user-list file.

# Get the list of running ACLs

```
curl -H "Arataga-Admin-Token: ABC" http://localhost:8080/acls
```

# Get the current stats

```
curl -H "Arataga-Admin-Token: ABC" http://localhost:8080/stats
```

# Perform a test authentification by IP-address

```
curl -H "Arataga-Admin-Token: ABC" "http://localhost:8080/debug/auth?proxy-in-addr=192.168.1.104&proxy-port=3010&user-ip=192.168.1.104&target-host=yandex.ru&target-port=80"
```

NOTE: URL should to be enclosed into quotes.

# Perform a test authentification by login/password

```
curl -H "Arataga-Admin-Token: ABC" "http://localhost:8080/debug/auth?proxy-in-addr=192.168.1.104&proxy-port=3010&user-ip=192.168.1.104&target-host=yandex.ru&target-port=80&username=user-name&password=user-password"
```

NOTE: URL should to be enclosed into quotes.

# Perform a test DNS lookup

```
curl -H "Arataga-Admin-Token: ABC" "http://localhost:8080/debug/dns-resolve?proxy-in-addr=127.0.0.1&proxy-port=3010&target-host=google.com&ip-version=IPv4"
```

NOTE: URL should to be enclosed into quotes.

