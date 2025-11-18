// ============================================================================
// MENADŻER LOGÓW - Centralne zarządzanie logami operacji kryptograficznych
// Singleton pattern dla globalnego dostępu do logów
// ============================================================================

import AsyncStorage from '@react-native-async-storage/async-storage';
import { CryptoLogEntry, LogStep, LogFilter, LogStats } from '../types/LogTypes';

const STORAGE_KEY = '@crypto_logs';
const MAX_LOGS = 100; // Maksymalna liczba przechowywanych logów

class LogManager {
  private static instance: LogManager;
  private logs: CryptoLogEntry[] = [];
  private currentSteps: LogStep[] = [];
  private currentStartTime: number = 0;
  private listeners: Set<() => void> = new Set();

  private constructor() {
    this.loadLogs();
  }

  /**
   * Singleton - pobierz instancję LogManagera
   */
  static getInstance(): LogManager {
    if (!LogManager.instance) {
      LogManager.instance = new LogManager();
    }
    return LogManager.instance;
  }

  /**
   * Rozpocznij nowy log operacji
   */
  startOperation(): void {
    this.currentSteps = [];
    this.currentStartTime = Date.now();
  }

  /**
   * Dodaj krok do bieżącej operacji
   */
  addStep(description: string, input?: string, output?: string, details?: string): void {
    const step: LogStep = {
      stepNumber: this.currentSteps.length + 1,
      description,
      input,
      output,
      details,
      timestamp: Date.now(),
    };
    this.currentSteps.push(step);
  }

  /**
   * Zakończ operację i zapisz log
   */
  async finishOperation(
    algorithm: string,
    algorithmName: string,
    operation: 'encrypt' | 'decrypt',
    inputText: string,
    outputText: string,
    key: string,
    success: boolean,
    error?: string,
    mode?: string
  ): Promise<void> {
    const duration = Date.now() - this.currentStartTime;
    
    const logEntry: CryptoLogEntry = {
      id: `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: Date.now(),
      algorithm,
      algorithmName,
      operation,
      inputText: inputText.length > 500 ? inputText.substring(0, 500) + '...' : inputText,
      outputText: outputText.length > 500 ? outputText.substring(0, 500) + '...' : outputText,
      key: this.maskKey(key, algorithm),
      mode,
      success,
      error,
      steps: [...this.currentSteps],
      duration,
    };

    this.logs.unshift(logEntry); // Dodaj na początek tablicy

    // Ogranicz liczbę logów
    if (this.logs.length > MAX_LOGS) {
      this.logs = this.logs.slice(0, MAX_LOGS);
    }

    await this.saveLogs();
    this.notifyListeners();
    
    // Wyczyść bieżące kroki
    this.currentSteps = [];
  }

  /**
   * Maskuj wrażliwe dane w kluczu (pokazuj tylko fragment)
   */
  private maskKey(key: string, algorithm: string): string {
    // Dla RSA i innych długich kluczy pokazuj tylko początek i koniec
    if (key.length > 50) {
      return `${key.substring(0, 20)}...${key.substring(key.length - 20)}`;
    }
    return key;
  }

  /**
   * Pobierz wszystkie logi
   */
  getLogs(): CryptoLogEntry[] {
    return [...this.logs];
  }

  /**
   * Pobierz logi z filtrem
   */
  getFilteredLogs(filter: LogFilter): CryptoLogEntry[] {
    return this.logs.filter((log) => {
      if (filter.algorithm && log.algorithm !== filter.algorithm) {
        return false;
      }
      if (filter.operation && log.operation !== filter.operation) {
        return false;
      }
      if (filter.dateFrom && log.timestamp < filter.dateFrom) {
        return false;
      }
      if (filter.dateTo && log.timestamp > filter.dateTo) {
        return false;
      }
      if (filter.successOnly && !log.success) {
        return false;
      }
      return true;
    });
  }

  /**
   * Pobierz pojedynczy log po ID
   */
  getLogById(id: string): CryptoLogEntry | undefined {
    return this.logs.find((log) => log.id === id);
  }

  /**
   * Pobierz statystyki
   */
  getStats(): LogStats {
    const stats: LogStats = {
      totalOperations: this.logs.length,
      successfulOperations: 0,
      failedOperations: 0,
      byAlgorithm: {},
      byOperation: {
        encrypt: 0,
        decrypt: 0,
      },
    };

    this.logs.forEach((log) => {
      if (log.success) {
        stats.successfulOperations++;
      } else {
        stats.failedOperations++;
      }

      stats.byAlgorithm[log.algorithm] = (stats.byAlgorithm[log.algorithm] || 0) + 1;
      stats.byOperation[log.operation]++;
    });

    return stats;
  }

  /**
   * Wyczyść wszystkie logi
   */
  async clearLogs(): Promise<void> {
    this.logs = [];
    await this.saveLogs();
    this.notifyListeners();
  }

  /**
   * Usuń pojedynczy log
   */
  async deleteLog(id: string): Promise<void> {
    this.logs = this.logs.filter((log) => log.id !== id);
    await this.saveLogs();
    this.notifyListeners();
  }

  /**
   * Zapisz logi do AsyncStorage
   */
  private async saveLogs(): Promise<void> {
    try {
      await AsyncStorage.setItem(STORAGE_KEY, JSON.stringify(this.logs));
    } catch (error) {
      console.error('Błąd podczas zapisywania logów:', error);
    }
  }

  /**
   * Wczytaj logi z AsyncStorage
   */
  private async loadLogs(): Promise<void> {
    try {
      const logsJson = await AsyncStorage.getItem(STORAGE_KEY);
      if (logsJson) {
        this.logs = JSON.parse(logsJson);
      }
    } catch (error) {
      console.error('Błąd podczas wczytywania logów:', error);
      this.logs = [];
    }
  }

  /**
   * Dodaj listener do zmian w logach
   */
  addListener(callback: () => void): () => void {
    this.listeners.add(callback);
    // Zwróć funkcję do usunięcia listenera
    return () => {
      this.listeners.delete(callback);
    };
  }

  /**
   * Powiadom wszystkich listenerów o zmianie
   */
  private notifyListeners(): void {
    this.listeners.forEach((callback) => callback());
  }

  /**
   * Eksportuj logi do JSON
   */
  exportLogs(): string {
    return JSON.stringify(this.logs, null, 2);
  }

  /**
   * Importuj logi z JSON
   */
  async importLogs(jsonString: string): Promise<void> {
    try {
      const importedLogs = JSON.parse(jsonString);
      if (Array.isArray(importedLogs)) {
        this.logs = importedLogs;
        await this.saveLogs();
        this.notifyListeners();
      }
    } catch (error) {
      throw new Error('Nieprawidłowy format danych logów');
    }
  }
}

export default LogManager.getInstance();
