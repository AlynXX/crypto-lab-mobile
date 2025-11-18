// ============================================================================
// TYPY I INTERFEJSY DLA SYSTEMU LOGOWANIA
// System rejestruje szczegółowe kroki operacji kryptograficznych
// ============================================================================

/**
 * Krok w procesie szyfrowania/deszyfrowania
 * Reprezentuje pojedynczą operację w algorytmie
 */
export interface LogStep {
  stepNumber: number;
  description: string;
  input?: string;
  output?: string;
  details?: string;
  timestamp: number;
}

/**
 * Kompletny wpis logu dla pojedynczej operacji
 */
export interface CryptoLogEntry {
  id: string;
  timestamp: number;
  algorithm: string;
  algorithmName: string;
  operation: 'encrypt' | 'decrypt';
  inputText: string;
  outputText: string;
  key: string;
  mode?: string; // Dla algorytmów z trybami (np. AES: ECB, CBC, CTR)
  success: boolean;
  error?: string;
  steps: LogStep[];
  duration: number; // czas wykonania w ms
}

/**
 * Filtr dla wyszukiwania logów
 */
export interface LogFilter {
  algorithm?: string;
  operation?: 'encrypt' | 'decrypt';
  dateFrom?: number;
  dateTo?: number;
  successOnly?: boolean;
}

/**
 * Statystyki logów
 */
export interface LogStats {
  totalOperations: number;
  successfulOperations: number;
  failedOperations: number;
  byAlgorithm: Record<string, number>;
  byOperation: {
    encrypt: number;
    decrypt: number;
  };
}
