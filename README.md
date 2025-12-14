# CryptoLab Mobile

Mobilna aplikacja do nauki kryptografii zbudowana w React Native z Expo.

## Funkcjonalności

### Szyfry klasyczne
- 🔐 **Szyfr Cezara** - klasyczny szyfr substytucyjny z przesunięciem
- 🔠 **Szyfr Vigenère'a** - polialfabetyczny szyfr z kluczem słownym
- 📖 **Szyfr z kluczem bieżącym** - wariant Vigenère'a z długim kluczem (One-Time Pad)

### Szyfry symetryczne
- 🔒 **AES** - Advanced Encryption Standard z trybami ECB, CBC, CTR

### Kryptografia asymetryczna
- 🔑 **RSA** - szyfrowanie z kluczem publicznym/prywatnym
- 🎲 **ElGamal** - szyfrowanie oparte na logarytmie dyskretnym
- 🔐 **ECDH** - wymiana kluczy na krzywych eliptycznych (ECIES)

### Funkcje skrótu i podpisy cyfrowe
- #️⃣ **SHA-256** - kryptograficzna funkcja skrótu (256-bit)
- ✍️ **Podpis Elektroniczny** - podpisy cyfrowe RSA-SHA256

### Funkcjonalności aplikacji
- 📝 **Tryb tekstowy** - bezpośrednie wprowadzanie tekstu
- 📁 **Tryb plików** - wczytywanie i zapisywanie plików tekstowych
- 🔄 **Szyfrowanie i deszyfrowanie** - operacje kryptograficzne
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

### 4. AES (Advanced Encryption Standard)
- **Typ**: Szyfr blokowy symetryczny
- **Klucze**: 128, 192 lub 256 bitów (hex)
- **Tryby**: ECB, CBC, CTR
- **Historia**: Standard NIST od 2001 roku
- **Zastosowanie**: SSL/TLS, bankowość, szyfrowanie dysków

### 5. RSA (Rivest-Shamir-Adleman)
- **Typ**: Kryptografia asymetryczna
- **Klucze**: Para publiczny/prywatny (512-bit edukacyjny)
- **Operacje**: c = m^e mod n, m = c^d mod n
- **Zastosowanie**: SSL/TLS, podpisy cyfrowe, PKI

### 6. ElGamal
- **Typ**: Kryptografia asymetryczna
- **Podstawa**: Problem logarytmu dyskretnego
- **Cechy**: Niedeterministyczny (ten sam tekst → różne szyfrogramy)
- **Szyfrogram**: Para liczb (a, b) dla każdego znaku

### 7. ECDH (Elliptic Curve Diffie-Hellman)
- **Typ**: Wymiana kluczy na krzywych eliptycznych
- **Implementacja**: ECIES (Elliptic Curve Integrated Encryption Scheme)
- **Zalety**: Krótsze klucze (256-bit ECC ≈ 3072-bit RSA)
- **Zastosowanie**: TLS 1.3, Signal, Bitcoin

### 8. SHA-256
- **Typ**: Kryptograficzna funkcja skrótu
- **Wyjście**: 256 bitów (64 znaki hex)
- **Cechy**: Jednokierunkowość, efekt lawiny, odporność na kolizje
- **Algorytm**: 64 rundy kompresji, operacje bitowe
- **Zastosowanie**: Bitcoin, SSL/TLS, podpisy cyfrowe

### 9. Podpis Elektroniczny
- **Typ**: Podpis cyfrowy RSA-SHA256
- **Schemat**: Hash dokumentu → Podpisanie kluczem prywatnym → Weryfikacja kluczem publicznym
- **Format**: dokument|hash|podpis|klucz_publiczny
- **Gwarancje**: Autentyczność, integralność, niezaprzeczalność
- **Zastosowanie**: eIDAS, SSL/TLS, podpisywanie oprogramowania

## Architektura

Aplikacja wykorzystuje **Strategy Pattern** dla algorytmów kryptograficznych. Wszystkie algorytmy są implementowane ręcznie, bez gotowych bibliotek kryptograficznych, co pomaga w zrozumieniu ich działania.

### Struktura projektu

```
crypto-lab-mobile/
├── src/
│   ├── algorithms/          # Implementacje algorytmów
│   │   ├── CryptographicAlgorithm.ts    # Klasa bazowa
│   │   ├── CaesarCipher.ts              # Szyfr Cezara
│   │   ├── VigenereCipher.ts            # Szyfr Vigenère'a
│   │   ├── RunningKeyCipher.ts          # Szyfr z kluczem bieżącym
│   │   ├── AESCipher.ts                 # AES (ECB/CBC/CTR)
│   │   ├── RSACipher.ts                 # RSA
│   │   ├── ElGamalCipher.ts             # ElGamal
│   │   ├── ECDHAlgorithm.ts             # ECDH/ECIES
│   │   ├── SHA256Hash.ts                # SHA-256
│   │   ├── DigitalSignature.ts          # Podpis cyfrowy
│   │   └── AlgorithmRegistry.ts         # Rejestr algorytmów
│   ├── components/          # Komponenty UI
│   │   ├── AlgorithmSidebar.tsx
│   │   └── LogsViewer.tsx
│   ├── types/              # Typy TypeScript
│   │   └── LogTypes.ts
│   └── utils/              # Funkcje pomocnicze
│       ├── fileUtils.ts
│       └── LogManager.ts
├── assets/                 # Zasoby (ikony, obrazy)
├── dokumentacja/           # Dokumentacja LaTeX
│   ├── main.tex
│   └── img/               # Zrzuty ekranu
├── App.tsx                # Główny komponent aplikacji
├── app.json              # Konfiguracja Expo
├── package.json
├── tsconfig.json
├── README.md
└── VISUALIZATION.md       # Wizualizacja struktur danych
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

**SHA-256:**
- Tekst: `Hello World`
- Wynik: `a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e`

**Podpis Elektroniczny:**
- Dokument: `Ala ma kota`
- Operacja: "Podpisz dokument"
- Wynik: `Ala ma kota|hash|podpis|3233,17`
- Weryfikacja: Wklej cały podpis i kliknij "Weryfikuj podpis"

## Changelog

### 14.12.2025
- ✨ **Implementacja SHA-256** - kryptograficzna funkcja skrótu
  - 64 rundy kompresji z funkcjami logicznymi Ch, Maj, Σ, σ
  - Preprocessing z paddingiem i dodawaniem długości
  - Jednokierunkowość - brak deszyfrowania
  - Zastosowanie w podpisach cyfrowych i blockchain
- ✨ **Implementacja Podpisu Elektronicznego** - RSA-SHA256
  - Podpisywanie: hash^d mod n kluczem prywatnym
  - Weryfikacja: signature^e mod n kluczem publicznym
  - Format: dokument|hash|podpis|klucz_publiczny
  - Gwarancje: autentyczność, integralność, niezaprzeczalność
  - Parametry edukacyjne: p=61, q=53, n=3233, e=17, d=2753
- 📚 **Rozbudowa dokumentacji LaTeX**
  - Dodano pełne sekcje dla SHA-256 i Podpisu Elektronicznego
  - Teoria matematyczna, algorytmy, bezpieczeństwo, zastosowania
  - Zrzuty ekranu procesu podpisywania i weryfikacji
  - Rozszerzono sekcję szyfru z kluczem bieżącym (One-Time Pad)
- 🎨 **Aktualizacja UI**
  - Warunkowe renderowanie pól (SHA-256 bez klucza)
  - Przyciski kontekstowe: "Haszuj", "Podpisz dokument", "Weryfikuj podpis"
  - Panele informacyjne dla nowych algorytmów

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
- ✨ Implementacja ElGamal (logarytm dyskretny)
- ✨ Implementacja ECDH/ECIES (krzywe eliptyczne)

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





