// ============================================================================
// KOMPONENT WYŚWIETLANIA LOGÓW
// Pokazuje historię operacji kryptograficznych z możliwością analizy krok po kroku
// ============================================================================

import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  Modal,
  Alert,
  RefreshControl,
  Platform,
} from 'react-native';
import { MaterialIcons } from '@expo/vector-icons';
import LogManager from '../utils/LogManager';
import { CryptoLogEntry, LogStep, LogStats } from '../types/LogTypes';
import * as Clipboard from 'expo-clipboard';

export default function LogsViewer() {
  const [logs, setLogs] = useState<CryptoLogEntry[]>([]);
  const [selectedLog, setSelectedLog] = useState<CryptoLogEntry | null>(null);
  const [showStepsModal, setShowStepsModal] = useState(false);
  const [stats, setStats] = useState<LogStats | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [filter, setFilter] = useState<'all' | 'encrypt' | 'decrypt'>('all');

  useEffect(() => {
    loadLogs();
    
    // Nasłuchuj zmian w logach
    const unsubscribe = LogManager.addListener(() => {
      loadLogs();
    });

    return unsubscribe;
  }, [filter]);

  const loadLogs = () => {
    const allLogs = LogManager.getLogs();
    const filteredLogs = filter === 'all' 
      ? allLogs 
      : allLogs.filter(log => log.operation === filter);
    setLogs(filteredLogs);
    setStats(LogManager.getStats());
  };

  const onRefresh = () => {
    setRefreshing(true);
    loadLogs();
    setRefreshing(false);
  };

  const handleViewSteps = (log: CryptoLogEntry) => {
    setSelectedLog(log);
    setShowStepsModal(true);
  };

  const handleDeleteLog = (id: string) => {
    Alert.alert(
      'Usuń log',
      'Czy na pewno chcesz usunąć ten log?',
      [
        { text: 'Anuluj', style: 'cancel' },
        {
          text: 'Usuń',
          style: 'destructive',
          onPress: async () => {
            await LogManager.deleteLog(id);
          },
        },
      ]
    );
  };

  const handleClearAllLogs = () => {
    Alert.alert(
      'Wyczyść wszystkie logi',
      'Czy na pewno chcesz usunąć wszystkie logi? Tej operacji nie można cofnąć.',
      [
        { text: 'Anuluj', style: 'cancel' },
        {
          text: 'Wyczyść',
          style: 'destructive',
          onPress: async () => {
            await LogManager.clearLogs();
          },
        },
      ]
    );
  };

  const handleCopyOutput = async (text: string) => {
    try {
      await Clipboard.setStringAsync(text);
      Alert.alert('Sukces', 'Tekst skopiowany do schowka');
    } catch (err) {
      Alert.alert('Błąd', 'Nie udało się skopiować tekstu');
    }
  };

  const formatDate = (timestamp: number): string => {
    const date = new Date(timestamp);
    return date.toLocaleString('pl-PL', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  };

  const formatDuration = (ms: number): string => {
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(2)}s`;
  };

  const renderStats = () => {
    if (!stats) return null;

    return (
      <View style={styles.statsContainer}>
        <Text style={styles.statsTitle}>📊 Statystyki</Text>
        <View style={styles.statsGrid}>
          <View style={styles.statItem}>
            <Text style={styles.statValue}>{stats.totalOperations}</Text>
            <Text style={styles.statLabel}>Operacji</Text>
          </View>
          <View style={styles.statItem}>
            <Text style={[styles.statValue, styles.successText]}>
              {stats.successfulOperations}
            </Text>
            <Text style={styles.statLabel}>Udanych</Text>
          </View>
          <View style={styles.statItem}>
            <Text style={[styles.statValue, styles.errorText]}>
              {stats.failedOperations}
            </Text>
            <Text style={styles.statLabel}>Błędnych</Text>
          </View>
          <View style={styles.statItem}>
            <Text style={styles.statValue}>{stats.byOperation.encrypt}</Text>
            <Text style={styles.statLabel}>Szyfrowanie</Text>
          </View>
          <View style={styles.statItem}>
            <Text style={styles.statValue}>{stats.byOperation.decrypt}</Text>
            <Text style={styles.statLabel}>Deszyfrowanie</Text>
          </View>
        </View>
      </View>
    );
  };

  const renderLogItem = (log: CryptoLogEntry) => {
    return (
      <View key={log.id} style={styles.logCard}>
        <View style={styles.logHeader}>
          <View style={styles.logHeaderLeft}>
            <View
              style={[
                styles.operationBadge,
                log.operation === 'encrypt'
                  ? styles.operationBadgeEncrypt
                  : styles.operationBadgeDecrypt,
              ]}
            >
              <MaterialIcons
                name={log.operation === 'encrypt' ? 'lock' : 'lock-open'}
                size={16}
                color="#fff"
              />
              <Text style={styles.operationBadgeText}>
                {log.operation === 'encrypt' ? 'Szyfrowanie' : 'Deszyfrowanie'}
              </Text>
            </View>
            {log.success ? (
              <MaterialIcons name="check-circle" size={20} color="#10b981" />
            ) : (
              <MaterialIcons name="error" size={20} color="#ef4444" />
            )}
          </View>
          <TouchableOpacity
            onPress={() => handleDeleteLog(log.id)}
            style={styles.deleteButton}
          >
            <MaterialIcons name="delete" size={20} color="#ef4444" />
          </TouchableOpacity>
        </View>

        <View style={styles.logBody}>
          <Text style={styles.algorithmName}>{log.algorithmName}</Text>
          {log.mode && (
            <Text style={styles.modeText}>Tryb: {log.mode}</Text>
          )}
          <Text style={styles.timestampText}>{formatDate(log.timestamp)}</Text>
          <Text style={styles.durationText}>
            Czas wykonania: {formatDuration(log.duration)}
          </Text>

          <View style={styles.textSection}>
            <Text style={styles.textLabel}>Dane wejściowe:</Text>
            <Text style={styles.textContent} numberOfLines={2}>
              {log.inputText}
            </Text>
          </View>

          <View style={styles.textSection}>
            <Text style={styles.textLabel}>Wynik:</Text>
            <Text style={styles.textContent} numberOfLines={2}>
              {log.outputText}
            </Text>
          </View>

          {log.error && (
            <View style={styles.errorSection}>
              <MaterialIcons name="error" size={16} color="#ef4444" />
              <Text style={styles.errorText}>{log.error}</Text>
            </View>
          )}

          <View style={styles.logActions}>
            {log.steps.length > 0 && (
              <TouchableOpacity
                style={styles.actionButton}
                onPress={() => handleViewSteps(log)}
              >
                <MaterialIcons name="list" size={16} color="#a78bfa" />
                <Text style={styles.actionButtonText}>
                  Kroki ({log.steps.length})
                </Text>
              </TouchableOpacity>
            )}
            <TouchableOpacity
              style={styles.actionButton}
              onPress={() => handleCopyOutput(log.outputText)}
            >
              <MaterialIcons name="content-copy" size={16} color="#a78bfa" />
              <Text style={styles.actionButtonText}>Kopiuj wynik</Text>
            </TouchableOpacity>
          </View>
        </View>
      </View>
    );
  };

  const renderStepsModal = () => {
    if (!selectedLog) return null;

    return (
      <Modal
        visible={showStepsModal}
        animationType="slide"
        transparent={true}
        onRequestClose={() => setShowStepsModal(false)}
      >
        <View style={styles.modalOverlay}>
          <View style={styles.modalContent}>
            <View style={styles.modalHeader}>
              <Text style={styles.modalTitle}>
                Analiza krok po kroku
              </Text>
              <TouchableOpacity
                onPress={() => setShowStepsModal(false)}
                style={styles.closeButton}
              >
                <MaterialIcons name="close" size={24} color="#fff" />
              </TouchableOpacity>
            </View>

            <ScrollView style={styles.stepsContainer}>
              <View style={styles.modalInfoSection}>
                <Text style={styles.modalInfoText}>
                  Algorytm: {selectedLog.algorithmName}
                </Text>
                <Text style={styles.modalInfoText}>
                  Operacja: {selectedLog.operation === 'encrypt' ? 'Szyfrowanie' : 'Deszyfrowanie'}
                </Text>
                <Text style={styles.modalInfoText}>
                  Liczba kroków: {selectedLog.steps.length}
                </Text>
              </View>

              {selectedLog.steps.map((step) => (
                <View key={step.stepNumber} style={styles.stepCard}>
                  <View style={styles.stepHeader}>
                    <View style={styles.stepNumber}>
                      <Text style={styles.stepNumberText}>{step.stepNumber}</Text>
                    </View>
                    <Text style={styles.stepDescription}>{step.description}</Text>
                  </View>

                  {step.input && (
                    <View style={styles.stepDetail}>
                      <Text style={styles.stepDetailLabel}>Wejście:</Text>
                      <Text style={styles.stepDetailValue}>{step.input}</Text>
                    </View>
                  )}

                  {step.output && (
                    <View style={styles.stepDetail}>
                      <Text style={styles.stepDetailLabel}>Wyjście:</Text>
                      <Text style={styles.stepDetailValue}>{step.output}</Text>
                    </View>
                  )}

                  {step.details && (
                    <View style={styles.stepDetail}>
                      <Text style={styles.stepDetailLabel}>Szczegóły:</Text>
                      <Text style={styles.stepDetailValue}>{step.details}</Text>
                    </View>
                  )}
                </View>
              ))}
            </ScrollView>
          </View>
        </View>
      </Modal>
    );
  };

  return (
    <View style={styles.container}>
      {/* Header z filtrem */}
      <View style={styles.header}>
        <Text style={styles.headerTitle}>📜 Historia operacji</Text>
        <TouchableOpacity
          onPress={handleClearAllLogs}
          style={styles.clearButton}
        >
          <MaterialIcons name="delete-sweep" size={20} color="#ef4444" />
          <Text style={styles.clearButtonText}>Wyczyść</Text>
        </TouchableOpacity>
      </View>

      {/* Filter */}
      <View style={styles.filterContainer}>
        <TouchableOpacity
          style={[styles.filterButton, filter === 'all' && styles.filterButtonActive]}
          onPress={() => setFilter('all')}
        >
          <Text style={[styles.filterButtonText, filter === 'all' && styles.filterButtonTextActive]}>
            Wszystkie
          </Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.filterButton, filter === 'encrypt' && styles.filterButtonActive]}
          onPress={() => setFilter('encrypt')}
        >
          <Text style={[styles.filterButtonText, filter === 'encrypt' && styles.filterButtonTextActive]}>
            Szyfrowanie
          </Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.filterButton, filter === 'decrypt' && styles.filterButtonActive]}
          onPress={() => setFilter('decrypt')}
        >
          <Text style={[styles.filterButtonText, filter === 'decrypt' && styles.filterButtonTextActive]}>
            Deszyfrowanie
          </Text>
        </TouchableOpacity>
      </View>

      {renderStats()}

      <ScrollView
        style={styles.logsContainer}
        refreshControl={
          <RefreshControl refreshing={refreshing} onRefresh={onRefresh} />
        }
      >
        {logs.length === 0 ? (
          <View style={styles.emptyContainer}>
            <MaterialIcons name="history" size={64} color="#475569" />
            <Text style={styles.emptyText}>Brak logów</Text>
            <Text style={styles.emptySubtext}>
              Wykonaj operację szyfrowania lub deszyfrowania, aby zobaczyć logi
            </Text>
          </View>
        ) : (
          logs.map(renderLogItem)
        )}
      </ScrollView>

      {renderStepsModal()}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0f172a',
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 16,
    backgroundColor: '#1e293b',
    borderBottomWidth: 1,
    borderBottomColor: '#334155',
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    color: '#fff',
  },
  clearButton: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
    padding: 8,
  },
  clearButtonText: {
    color: '#ef4444',
    fontSize: 14,
    fontWeight: '600',
  },
  filterContainer: {
    flexDirection: 'row',
    padding: 12,
    gap: 8,
    backgroundColor: '#1e293b',
  },
  filterButton: {
    flex: 1,
    paddingVertical: 8,
    paddingHorizontal: 12,
    borderRadius: 8,
    backgroundColor: '#334155',
    alignItems: 'center',
  },
  filterButtonActive: {
    backgroundColor: '#a78bfa',
  },
  filterButtonText: {
    color: '#cbd5e1',
    fontSize: 14,
    fontWeight: '600',
  },
  filterButtonTextActive: {
    color: '#fff',
  },
  statsContainer: {
    padding: 16,
    backgroundColor: '#1e293b',
    marginBottom: 8,
  },
  statsTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#fff',
    marginBottom: 12,
  },
  statsGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 12,
  },
  statItem: {
    flex: 1,
    minWidth: 80,
    backgroundColor: '#334155',
    padding: 12,
    borderRadius: 8,
    alignItems: 'center',
  },
  statValue: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#a78bfa',
    marginBottom: 4,
  },
  statLabel: {
    fontSize: 12,
    color: '#cbd5e1',
  },
  successText: {
    color: '#10b981',
  },
  logsContainer: {
    flex: 1,
    padding: 12,
  },
  logCard: {
    backgroundColor: '#1e293b',
    borderRadius: 12,
    marginBottom: 12,
    borderWidth: 1,
    borderColor: '#334155',
  },
  logHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 12,
    borderBottomWidth: 1,
    borderBottomColor: '#334155',
  },
  logHeaderLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  operationBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
    paddingVertical: 4,
    paddingHorizontal: 8,
    borderRadius: 12,
  },
  operationBadgeEncrypt: {
    backgroundColor: '#10b981',
  },
  operationBadgeDecrypt: {
    backgroundColor: '#3b82f6',
  },
  operationBadgeText: {
    color: '#fff',
    fontSize: 12,
    fontWeight: '600',
  },
  deleteButton: {
    padding: 4,
  },
  logBody: {
    padding: 12,
  },
  algorithmName: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#a78bfa',
    marginBottom: 4,
  },
  modeText: {
    fontSize: 14,
    color: '#cbd5e1',
    marginBottom: 4,
  },
  timestampText: {
    fontSize: 12,
    color: '#94a3b8',
    marginBottom: 2,
  },
  durationText: {
    fontSize: 12,
    color: '#94a3b8',
    marginBottom: 12,
  },
  textSection: {
    marginBottom: 12,
  },
  textLabel: {
    fontSize: 12,
    color: '#94a3b8',
    marginBottom: 4,
    fontWeight: '600',
  },
  textContent: {
    fontSize: 14,
    color: '#cbd5e1',
    backgroundColor: '#334155',
    padding: 8,
    borderRadius: 6,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
  },
  errorSection: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    padding: 8,
    backgroundColor: '#7f1d1d',
    borderRadius: 6,
    marginBottom: 12,
  },
  errorText: {
    flex: 1,
    fontSize: 12,
    color: '#fca5a5',
  },
  logActions: {
    flexDirection: 'row',
    gap: 8,
  },
  actionButton: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 4,
    paddingVertical: 8,
    paddingHorizontal: 12,
    backgroundColor: '#334155',
    borderRadius: 8,
  },
  actionButtonText: {
    color: '#a78bfa',
    fontSize: 12,
    fontWeight: '600',
  },
  emptyContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 40,
  },
  emptyText: {
    fontSize: 18,
    fontWeight: 'bold',
    color: '#cbd5e1',
    marginTop: 16,
  },
  emptySubtext: {
    fontSize: 14,
    color: '#94a3b8',
    textAlign: 'center',
    marginTop: 8,
  },
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.8)',
    justifyContent: 'flex-end',
  },
  modalContent: {
    backgroundColor: '#1e293b',
    borderTopLeftRadius: 24,
    borderTopRightRadius: 24,
    maxHeight: '90%',
  },
  modalHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 20,
    borderBottomWidth: 1,
    borderBottomColor: '#334155',
  },
  modalTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    color: '#fff',
  },
  closeButton: {
    padding: 4,
  },
  modalInfoSection: {
    padding: 16,
    backgroundColor: '#334155',
    margin: 16,
    borderRadius: 12,
  },
  modalInfoText: {
    fontSize: 14,
    color: '#cbd5e1',
    marginBottom: 4,
  },
  stepsContainer: {
    padding: 16,
  },
  stepCard: {
    backgroundColor: '#334155',
    borderRadius: 12,
    padding: 12,
    marginBottom: 12,
    borderLeftWidth: 4,
    borderLeftColor: '#a78bfa',
  },
  stepHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    marginBottom: 8,
  },
  stepNumber: {
    width: 32,
    height: 32,
    borderRadius: 16,
    backgroundColor: '#a78bfa',
    justifyContent: 'center',
    alignItems: 'center',
  },
  stepNumberText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: 'bold',
  },
  stepDescription: {
    flex: 1,
    fontSize: 14,
    fontWeight: '600',
    color: '#fff',
  },
  stepDetail: {
    marginTop: 8,
    paddingTop: 8,
    borderTopWidth: 1,
    borderTopColor: '#475569',
  },
  stepDetailLabel: {
    fontSize: 12,
    color: '#94a3b8',
    fontWeight: '600',
    marginBottom: 4,
  },
  stepDetailValue: {
    fontSize: 13,
    color: '#cbd5e1',
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
  },
});
