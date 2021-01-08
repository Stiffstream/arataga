Примеры полезных для отладки вариантов запуска curl-а.

# Обновление конфигурации

```
curl -H "Arataga-Admin-Token: ABC" -H "Content-Type: text/plain" -X POST --data-binary @__locals/cfg/local-config.cfg http://localhost:8080/config
```

Указание ключа `--data-binary` обязательно. В противном случае curl поудаляет переводы строк в содержимом файла.

# Обновление списка пользователей

```
curl -H "Arataga-Admin-Token: ABC" -H "Content-Type: text/plain" -X POST --data-binary @__locals/cfg/user-list.cfg http://localhost:8080/users
```

Указание ключа `--data-binary` обязательно. В противном случае curl поудаляет переводы строк в содержимом файла.

# Получение списка запущенных ACL

```
curl -H "Arataga-Admin-Token: ABC" http://localhost:8080/acls
```

# Получение текущей статистики/мониторинговой информации

```
curl -H "Arataga-Admin-Token: ABC" http://localhost:8080/stats
```

# Провести тестовую аутентификацию пользователя по IP

```
curl -H "Arataga-Admin-Token: ABC" "http://localhost:8080/debug/auth?proxy-in-addr=192.168.1.104&proxy-port=3010&user-ip=192.168.1.104&target-host=yandex.ru&target-port=80"
```

Примечание: URL нужно заключить в кавычки.

# Провести тестовую аутентификацию пользователя по login/password

```
curl -H "Arataga-Admin-Token: ABC" "http://localhost:8080/debug/auth?proxy-in-addr=192.168.1.104&proxy-port=3010&user-ip=192.168.1.104&target-host=yandex.ru&target-port=80&username=user-name&password=user-password"
```

Примечание: URL нужно заключить в кавычки.

# Отправить тестовый запрос на разрешение имени

```
curl -H "Arataga-Admin-Token: ABC" "http://localhost:8080/debug/dns-resolve?proxy-in-addr=127.0.0.1&proxy-port=3010&target-host=google.com&ip-version=IPv4"
```

Примечание: URL нужно заключить в кавычки.
