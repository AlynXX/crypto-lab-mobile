# Wizualizacja działania algorytmów

## Szyfr Cezara - Wizualizacja przesunięcia

```
Alfabet oryginalny:  A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
                     ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓
Przesunięcie o 3:    D E F G H I J K L M N O P Q R S T U V W X Y Z A B C
```

### Przykład: HELLO → KHOOR

```
H → K (pozycja 7 + 3 = 10)
E → H (pozycja 4 + 3 = 7)
L → O (pozycja 11 + 3 = 14)
L → O (pozycja 11 + 3 = 14)
O → R (pozycja 14 + 3 = 17)
```

---

## Szyfr Vigenère'a - Wizualizacja tablicy

### Tabula Recta (uproszczona)

```
    A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
A   A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
B   B C D E F G H I J K L M N O P Q R S T U V W X Y Z A
C   C D E F G H I J K L M N O P Q R S T U V W X Y Z A B
D   D E F G H I J K L M N O P Q R S T U V W X Y Z A B C
E   E F G H I J K L M N O P Q R S T U V W X Y Z A B C D
...
```

### Przykład: ATTACK + LEMON = LXFOPV

```
Krok po kroku:

Tekst:     A    T    T    A    C    K
Klucz:     L    E    M    O    N    L
           ↓    ↓    ↓    ↓    ↓    ↓
Operacja: +11  +4  +12  +14  +13  +11
           ↓    ↓    ↓    ↓    ↓    ↓
Wynik:     L    X    F    O    P    V

Szczegółowo:
A (0)  + L (11) = 11  = L
T (19) + E (4)  = 23  = X
T (19) + M (12) = 31 mod 26 = 5 = F
A (0)  + O (14) = 14  = O
C (2)  + N (13) = 15  = P
K (10) + L (11) = 21  = V
```

---

## Porównanie długości klucza

### Szyfr Vigenère'a (klucz się powtarza)

```
Tekst:  A T T A C K A T D A W N I G H T
        │ │ │ │ │ │ │ │ │ │ │ │ │ │ │ │
Klucz:  L E M O N L E M O N L E M O N L
        └─┬─┘ └─┬─┘ └─┬─┘ └─┬─┘ └─┬─┘
      Klucz "LEMON" powtarza się w kółko
```

### Szyfr z kluczem bieżącym (klucz się NIE powtarza)

```
Tekst:  A T T A C K
        │ │ │ │ │ │
Klucz:  T H E Q U I  ← różne litery dla każdej pozycji
        C K B R O W
        N F O X J U
        ...
        (długi, niepowtarzający się klucz)
```

---

## Tablica Vigenère'a (pełna wersja)

```
      | A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
------+----------------------------------------------------
A     | A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
B     | B C D E F G H I J K L M N O P Q R S T U V W X Y Z A
C     | C D E F G H I J K L M N O P Q R S T U V W X Y Z A B
D     | D E F G H I J K L M N O P Q R S T U V W X Y Z A B C
E     | E F G H I J K L M N O P Q R S T U V W X Y Z A B C D
F     | F G H I J K L M N O P Q R S T U V W X Y Z A B C D E
G     | G H I J K L M N O P Q R S T U V W X Y Z A B C D E F
H     | H I J K L M N O P Q R S T U V W X Y Z A B C D E F G
I     | I J K L M N O P Q R S T U V W X Y Z A B C D E F G H
J     | J K L M N O P Q R S T U V W X Y Z A B C D E F G H I
K     | K L M N O P Q R S T U V W X Y Z A B C D E F G H I J
L     | L M N O P Q R S T U V W X Y Z A B C D E F G H I J K
M     | M N O P Q R S T U V W X Y Z A B C D E F G H I J K L
N     | N O P Q R S T U V W X Y Z A B C D E F G H I J K L M
O     | O P Q R S T U V W X Y Z A B C D E F G H I J K L M N
P     | P Q R S T U V W X Y Z A B C D E F G H I J K L M N O
Q     | Q R S T U V W X Y Z A B C D E F G H I J K L M N O P
R     | R S T U V W X Y Z A B C D E F G H I J K L M N O P Q
S     | S T U V W X Y Z A B C D E F G H I J K L M N O P Q R
T     | T U V W X Y Z A B C D E F G H I J K L M N O P Q R S
U     | U V W X Y Z A B C D E F G H I J K L M N O P Q R S T
V     | V W X Y Z A B C D E F G H I J K L M N O P Q R S T U
W     | W X Y Z A B C D E F G H I J K L M N O P Q R S T U V
X     | X Y Z A B C D E F G H I J K L M N O P Q R S T U V W
Y     | Y Z A B C D E F G H I J K L M N O P Q R S T U V W X
Z     | Z A B C D E F G H I J K L M N O P Q R S T U V W X Y
```

**Jak używać tablicy:**
1. Znajdź wiersz odpowiadający literze klucza (lewo)
2. Znajdź kolumnę odpowiadającą literze tekstu jawnego (góra)
3. Przecięcie = litera zaszyfrowana

**Przykład:** Litera `A` + klucz `L`:
- Wiersz `L`
- Kolumna `A`
- Przecięcie = `L`

---

## Matematyka za szyfrowaniem

### Konwersja litera ↔ liczba

```
A=0, B=1, C=2, D=3, E=4, F=5, G=6, H=7, I=8, J=9,
K=10, L=11, M=12, N=13, O=14, P=15, Q=16, R=17, S=18,
T=19, U=20, V=21, W=22, X=23, Y=24, Z=25
```

### Operacja modulo 26

```
Przykład: (19 + 12) mod 26
= 31 mod 26
= 5
(bo 31 - 26 = 5)

Dlaczego modulo?
Żeby "zawinąć" alfabet:
... W X Y Z → A B C ...
    22 23 24 25 → 0 1 2
```

### Wzory

**Szyfrowanie:**
```
C = (P + K) mod 26

gdzie:
C = litera zaszyfrowana
P = litera tekstu jawnego
K = litera klucza
```

**Deszyfrowanie:**
```
P = (C - K + 26) mod 26

Dlaczego +26?
Żeby uniknąć liczb ujemnych przed operacją modulo
```

---

## Analiza bezpieczeństwa - wizualna

### Szyfr Cezara - atak siłowy

```
Tylko 25 możliwości!

Klucz 1:  IFMMP XPSME
Klucz 2:  JGNNQ YQTNF
Klucz 3:  KHOOR ZRUOG  ← poprawny!
Klucz 4:  LIPPS ASVPH
...
Klucz 25: GDKKN VNQKC
```

### Szyfr Vigenère'a - powtarzający się wzór

```
Klucz: CAT

ATTACKATDAWNATTACKATDAWNATTACKATDAWN
CATCATCATCATCATCATCATCATCATCATCATCA  ← wzór!
CVVMCOCVFCZBMVVMCOCVFCZBMVVMCOCVFCZB

Zauważ powtórzenia w tekście zaszyfrowanym!
To słabość, którą wykorzystuje atak Kasiskiego.
```

### Szyfr z kluczem bieżącym - idealnie losowy

```
Klucz jest tak samo długi jak tekst i nigdy się nie powtarza:

ATTACK
QXJMPE  ← klucz losowy, unikalna dla każdej litery
QXCYPI  ← brak wzoru!

Ten sam tekst z innym kluczem daje CAŁKOWICIE inny wynik.
Teoretycznie NIE DO ZŁAMANIA!
```
