# CryptoLab Mobile

Mobilna aplikacja do nauki kryptografii zbudowana w React Native z Expo.

## Opis

CryptoLab Mobile to edukacyjna platforma do nauki algorytmów kryptograficznych. Aplikacja została przeniesiona z projektu webowego "projekt drozd" i zoptymalizowana dla urządzeń mobilnych.

## Funkcjonalności

- 🔐 **Szyfr Cezara** - klasyczny szyfr substytucyjny z przesunięciem
- 🔠 **Szyfr Vigenère'a** - polialfabetyczny szyfr z kluczem słownym
- 📖 **Szyfr z kluczem bieżącym** - wariant Vigenère'a z długim kluczem
-  **Tryb tekstowy** - bezpośrednie wprowadzanie tekstu
- 📁 **Tryb plików** - wczytywanie i zapisywanie plików tekstowych
- 🔄 **Szyfrowanie i deszyfrowanie**
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
│   │   └── AlgorithmRegistry.ts
│   ├── components/          # Komponenty UI
│   │   └── AlgorithmSidebar.tsx
│   └── utils/              # Funkcje pomocnicze
│       └── fileUtils.ts
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



