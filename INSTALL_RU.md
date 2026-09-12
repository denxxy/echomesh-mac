# Инструкция по установке, сборке и запуску EchoMesh macOS (`echomesh-mac`)

В данном руководстве подробно описан процесс развертывания, компиляции ядра `echomesh-core`, генерации Swift-биндингов UniFFI и запуска нативного клиента для macOS.

---

## 1. Системные требования

- **Операционная система:** macOS 14.0 (Sonoma) или новее.
- **Архитектура:** Apple Silicon (arm64) или Intel (x86_64).
- **Инструменты разработчика:**
  - [Xcode](https://developer.apple.com/xcode/) 15.0 или новее (либо Xcode Command Line Tools).
  - [Rust](https://rustup.rs/) версии 1.80+ с таргетами для macOS.

---

## 2. Подготовка окружения на macOS

### Шаг 1: Установка Command Line Tools
Если инструменты разработчика Apple еще не установлены, выполните в терминале:
```bash
xcode-select --install
```

### Шаг 2: Установка Rust
Установите официальный инструментарий Rust:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Добавьте таргеты компиляции для сборки XCFramework под macOS:
```bash
rustup target add aarch64-apple-darwin
rustup target add x86_64-apple-darwin
```

---

## 3. Клонирование репозитория

```bash
git clone https://github.com/denxxy/echomesh-mac.git
cd echomesh-mac
```

---

## 4. Быстрый запуск приложения

В проекте настроен вспомогательный скрипт для мгновенной компиляции и запуска приложения:

```bash
cd EchoMeshMac
./run.sh
```

Приложение соберется и запустится в строке меню (Menu Bar) macOS.

---

## 5. Полная пересборка стека (Rust Core + XCFramework + macOS App)

Если вы внесли изменения в протокол, ядро Rust или UniFFI-интерфейсы, запустите корневой скрипт сборки:

```bash
./build.sh
```

Этот скрипт выполняет:
1. Компиляцию `echomesh-core` в статическую библиотеку `libechomesh_core.a` для `aarch64` и `x86_64`.
2. Генерацию Swift-биндингов с помощью `uniffi-bindgen`.
3. Упаковку в нативный `EchoMeshCore.xcframework`.
4. Сборку Swift-пакета `EchoMeshMac`.

---

## 6. Запуск и отладка через Xcode

Вы можете открыть приложение напрямую в среде разработки Xcode:

```bash
open EchoMeshMac/Package.swift
```

1. Дождитесь разрешения локальных зависимостей и индексации фреймворка `EchoMeshCore.xcframework`.
2. Выберите схему **`EchoMeshMac`** и устройство **«My Mac»**.
3. Нажмите `Cmd + R` для запуска приложения.

---

## 7. Запуск автоматических тестов

### Тесты криптографического ядра (Rust):
```bash
cargo test --manifest-path echomesh-core/Cargo.toml
```

### Модульные тесты приложения Swift:
```bash
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift test --package-path EchoMeshMac
```

---

## 8. Сетевая конфигурация и параметры релея

Клиент по умолчанию настроен на взаимодействие с эталонным stateless-релеем:
- **Адрес релея:** `77.81.5.109:8443`
- **Протокол:** Noise NK (`Noise_NK_25519_ChaChaPoly_BLAKE2s`) с маскировкой под TLS 1.3 ClientHello (Pseudo-TLS).
- **Размер кадров:** строго 1420 байт с выравнивающим паддингом.
- **Хранение ключей:** Приватные идентификационные ключи сохраняются в системном Keychain macOS (`com.echomesh.mac.identity`).
- **Эхо-тестирование:** Для проверки задержки и целостности соединения отправьте сообщение в чат с `Echo Relay Node` (`[0xEE; 32]`).
