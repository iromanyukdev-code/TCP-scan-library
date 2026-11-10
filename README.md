# portscan

Go-библиотека для TCP-сканирования портов с ограничением конкурентности, таймаутами и graceful shutdown. Требуется Go 1.25.5 или новее.

## Запуск

Из корня проекта:

```sh
go run ./examples/graceful
```

Или `make run`. Пример проверяет `127.0.0.1`: порты 22, 80, 443 и 8000–8010, выводит результаты и завершается. SIGINT/SIGTERM запускают graceful shutdown с ожиданием до 5 секунд.

Хосты и порты можно изменить в [примере](examples/graceful/main.go). 

## Проверка

```sh
go test -race ./...
```

Полная проверка (тесты, vet, сборка и форматирование): `make check`.

Контракт API: [api/portscan.yaml](api/portscan.yaml).
