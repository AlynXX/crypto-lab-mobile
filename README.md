# CryptoLab Mobile

Mobilna aplikacja do nauki kryptografii zbudowana w React Native z Expo.

## Opis

CryptoLab Mobile to edukacyjna platforma do nauki algorytmów kryptograficznych. Aplikacja została przeniesiona z projektu webowego "projekt drozd" i zoptymalizowana dla urządzeń mobilnych.

## Funkcjonalności

- 🔐 **Szyfr Cezara** - klasyczny szyfr substytucyjny z przesunięciem
- 🔠 **Szyfr Vigenère'a** - polialfabetyczny szyfr z kluczem słownym
- 📖 **Szyfr z kluczem bieżącym** - wariant Vigenère'a z długim kluczem
- 🔒 **AES** - nowoczesny szyfr symetryczny z trybami ECB, CBC, CTR
- 🔑 **RSA** - algorytm kryptografii asymetrycznej z generowaniem kluczy
-  **Tryb tekstowy** - bezpośrednie wprowadzanie tekstu
- 📁 **Tryb plików** - wczytywanie i zapisywanie plików tekstowych
- 🔄 **Szyfrowanie i deszyfrowanie**
- 📊 **System logowania** - historia operacji z analizą krok po kroku
- 📈 **Statystyki** - analiza użycia algorytmów i czasu wykonania
- 📚 **Dokumentacja** - wbudowana dokumentacja algorytmów z historią i wzorami matematycznymi
- ⌨️ **Inteligentna obsługa klawiatury** - automatyczne dostosowanie widoku
- 🎨 **Ciemny interfejs** - przyjazny dla oczu

## Zaimplementowane algorytmy

### 1. Szyfr Cezara
- **Typ**: Szyfr monoalfabetyczny substytucyjny
- **Klucz**: Liczba 1-25 (przesunięcie w alfabecie)
- **Historia**: Używany przez Juliusza Cezara (~58 p.n.e.)
- **Wzór**: E(x) = (x + k) mod 26

### 2. Szyfr Vigenère'a
- **Typ**: Szyfr polialfabetyczny
- **Klucz**: Słowo lub fraza (tylko litery)
- **Historia**: Opracowany w XVI wieku, "le chiffre indéchiffrable"
- **Wzór**: E(x,k) = (x + k) mod 26
- **Przykład**: ATTACK + LEMON = LXFOPV

### 3. Szyfr z kluczem bieżącym
- **Typ**: Rozwinięcie Vigenère'a
- **Klucz**: Długi tekst (np. fragment książki)
- **Zaleta**: Przy losowym kluczu jednorazowym - teoretycznie nie do złamania
- **Wzór**: E(x,k) = (x + k) mod 26, gdzie |k| ≥ |x|

## Architektura

Aplikacja wykorzystuje **Strategy Pattern** dla algorytmów kryptograficznych. Wszystkie algorytmy są implementowane ręcznie, bez gotowych bibliotek kryptograficznych, co pomaga w zrozumieniu ich działania.

### Struktura projektu

```
crypto-lab-mobile/
├── src/
│   ├── algorithms/          # Implementacje algorytmów
│   │   ├── CryptographicAlgorithm.ts
│   │   ├── CaesarCipher.ts
│   │   ├── VigenereCipher.ts
│   │   ├── RunningKeyCipher.ts
│   │   ├── AESCipher.ts
│   │   ├── RSACipher.ts
│   │   └── AlgorithmRegistry.ts
│   ├── components/          # Komponenty UI
│   │   ├── AlgorithmSidebar.tsx
│   │   └── LogsViewer.tsx
│   ├── types/              # Typy TypeScript
│   │   └── LogTypes.ts
│   └── utils/              # Funkcje pomocnicze
│       ├── fileUtils.ts
│       └── LogManager.ts
├── App.tsx                 # Główny komponent aplikacji
├── app.json               # Konfiguracja Expo
└── package.json
```

## Instalacja

1. Sklonuj repozytorium lub skopiuj projekt
2. Zainstaluj zależności:
   ```bash
   npm install
   ```

## Uruchamianie

### Tryb deweloperski

```bash
npm start
```

### Na Androidzie

```bash
npm run android
```

### Na iOS

```bash
npm run ios
```

### W przeglądarce

```bash
npm run web
```

## Technologie

- **React Native** - framework do budowy aplikacji mobilnych
- **Expo** - platforma usprawniająca rozwój aplikacji RN
- **TypeScript** - typowany JavaScript
- **expo-document-picker** - wybieranie plików
- **expo-file-system** - operacje na plikach
- **expo-sharing** - udostępnianie plików
- **@expo/vector-icons** - ikony Material Design
- **@react-native-async-storage/async-storage** - przechowywanie logów lokalnie

## System logowania

Aplikacja zawiera zaawansowany system rejestrowania operacji kryptograficznych:

### Funkcje
- 📝 **Historia operacji** - automatyczne zapisywanie wszystkich operacji szyfrowania/deszyfrowania
- 🔍 **Analiza krok po kroku** - szczegółowy przebieg każdego algorytmu
- 📊 **Statystyki** - liczba operacji, najczęściej używany algorytm, czasy wykonania
- 🔒 **Bezpieczeństwo** - automatyczne maskowanie kluczy w logach
- 🗂️ **Filtrowanie** - wyświetlanie wszystkich operacji lub tylko szyfrowania/deszyfrowania
- 💾 **Persistent storage** - logi są zapisywane lokalnie (AsyncStorage)
- 🗑️ **Zarządzanie** - możliwość usuwania pojedynczych logów lub czyszczenia całej historii

### Rejestrowane informacje
Każdy log zawiera:
- Nazwę algorytmu i typ operacji (encrypt/decrypt)
- Tekst wejściowy i wyjściowy
- Klucz (maskowany dla bezpieczeństwa)
- Parametry (np. tryb AES)
- Status operacji i ewentualne błędy
- Czas wykonania w milisekundach
- Szczegółowe kroki algorytmu z danymi pośrednimi

### Architektura
- **LogManager** - Singleton zarządzający logami
- **LogsViewer** - Komponent UI do wyświetlania historii
- **LogTypes** - Definicje typów TypeScript

## Jak dodać nowy algorytm

1. Stwórz nową klasę rozszerzającą `CryptographicAlgorithm` w folderze `src/algorithms/`
2. Zaimplementuj metody:
   - `encrypt(plaintext: string, key: string): string`
   - `decrypt(ciphertext: string, key: string): string`
   - `validateKey(key: string): { valid: boolean; error?: string }`
   - `getKeyRequirements(): string`
3. Zarejestruj algorytm w `AlgorithmRegistry.ts` w metodzie `_registerDefaultAlgorithms()`

### Przykład:

```typescript
import CryptographicAlgorithm from './CryptographicAlgorithm';

export default class MojAlgorytm extends CryptographicAlgorithm {
  constructor() {
    super(
      'Nazwa algorytmu',
      'Opis algorytmu',
      'Kategoria'
    );
  }

  validateKey(key: string): { valid: boolean; error?: string } {
    // Walidacja klucza
    return { valid: true };
  }

  getKeyRequirements(): string {
    return 'Opis wymagań dla klucza';
  }

  encrypt(plaintext: string, key: string): string {
    // Implementacja szyfrowania
  }

  decrypt(ciphertext: string, key: string): string {
    // Implementacja deszyfrowania
  }
}
```

## Licencja

Projekt edukacyjny.

## Quick Start Guide

1. Zainstaluj zależności: `npm install`
2. Uruchom aplikację: `npm start`
3. Wybierz algorytm z menu (ikona menu w prawym górnym rogu)
4. Wprowadź tekst do zaszyfrowania
5. Kliknij "Zaszyfruj" lub "Deszyfruj"
6. Zobacz wynik i pobierz jako plik

### Szybkie przykłady

**Szyfr Cezara:**
- Tekst: `HELLO`
- Klucz: `3`
- Wynik: `KHOOR`

**Szyfr Vigenère'a:**
- Tekst: `ATTACK`
- Klucz: `LEMON`
- Wynik: `LXFOPV`

**Szyfr z kluczem bieżącym:**
- Tekst: `HELLO`
- Klucz: `THE QUICK BROWN FOX`
- Wynik: (zależy od pełnego klucza)

## Changelog

### 24.11.2025
- ✨ Implementacja zaawansowanego systemu logowania operacji
- 📊 Dodanie komponentu LogsViewer do wyświetlania historii
- 💾 Przechowywanie logów w AsyncStorage (max 100 wpisów)
- 🔍 Szczegółowe kroki algorytmów dla celów edukacyjnych
- 📈 Statystyki użycia algorytmów i czasów wykonania
- 🔒 Automatyczne maskowanie kluczy w logach
- 🗑️ Funkcje filtrowania, usuwania i eksportu logów

### 16.11.2025
- ✨ Implementacja algorytmu RSA (kryptografia asymetryczna)
- 🔑 Generator par kluczy publiczny/prywatny
- 🧮 Algorytmy: Euklides, rozszerzony Euklides, szybkie potęgowanie modularne
- 🎨 GUI do generowania kluczy RSA z możliwością kopiowania

### 28.10.2025
- ✨ Implementacja szyfru AES (Advanced Encryption Standard)
- 🔐 Obsługa trzech trybów pracy: ECB, CBC, CTR
- 🔑 Wsparcie dla kluczy AES-128, AES-192, AES-256
- 📦 Padding PKCS#7 i obsługa wektorów inicjalizujących (IV)

### 20.10.2025
- ✨ Dodanie szyfru Vigenère'a i szyfru z kluczem bieżącym
- 🎨 Ulepszenie interfejsu użytkownika
- 🏗️ Implementacja AlgorithmRegistry (Singleton)
- ✅ Ulepszona walidacja kluczy

### 14.10.2025
- 🎉 Pierwsza wersja z szyfrem Cezara
- 🎨 Podstawowe GUI





