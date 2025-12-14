import React, { useState } from 'react';
import {
  StyleSheet,
  Text,
  View,
  ScrollView,
  TextInput,
  TouchableOpacity,
  Modal,
  Alert,
  KeyboardAvoidingView,
  Platform,
  Keyboard,
  TouchableWithoutFeedback,
} from 'react-native';
import { StatusBar } from 'expo-status-bar';
import { SafeAreaView } from 'react-native-safe-area-context';
import { MaterialIcons } from '@expo/vector-icons';
import * as Clipboard from 'expo-clipboard';
import { registry } from './src/algorithms/AlgorithmRegistry';
import AlgorithmSidebar from './src/components/AlgorithmSidebar';
import LogsViewer from './src/components/LogsViewer';
import { pickTextFile, saveTextFile } from './src/utils/fileUtils';
import AESCipher from './src/algorithms/AESCipher';
import RSACipher from './src/algorithms/RSACipher';
import ECDHAlgorithm from './src/algorithms/ECDHAlgorithm';
import ElGamalCipher from './src/algorithms/ElGamalCipher';
import logManager from './src/utils/LogManager';

export default function App() {
  const [currentView, setCurrentView] = useState<'crypto' | 'logs'>('crypto');
  const [mode, setMode] = useState<'text' | 'file'>('text');
  const [operation, setOperation] = useState<'encrypt' | 'decrypt'>('encrypt');
  const [selectedAlgorithm, setSelectedAlgorithm] = useState('caesar');
  const [aesMode, setAesMode] = useState<'ECB' | 'CBC' | 'CTR'>('ECB');
  const [inputText, setInputText] = useState('');
  const [outputText, setOutputText] = useState('');
  const [key, setKey] = useState('3');
  const [error, setError] = useState('');
  const [showDocs, setShowDocs] = useState(false);
  const [showSidebar, setShowSidebar] = useState(false);
  const [showRSAKeysModal, setShowRSAKeysModal] = useState(false);
  const [rsaPublicKey, setRsaPublicKey] = useState('');
  const [rsaPrivateKey, setRsaPrivateKey] = useState('');

  const algorithms = registry.getAll();
  const currentAlgo = registry.get(selectedAlgorithm);

  // Funkcja pomocnicza do ustawienia domyślnego klucza
  const getDefaultKey = (algorithmId: string): string => {
    switch (algorithmId) {
      case 'caesar':
        return '3';
      case 'vigenere':
        return 'LEMON';
      case 'running-key':
        return 'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG';
      case 'aes':
        return AESCipher.DEFAULT_KEY;
      case 'ecdh':
        return '';
      case 'elgamal':
        return '';
      case 'sha256':
        return '';
      case 'digital-signature':
        return '';
      default:
        return '';
    }
  };

  // Obsługa zmiany algorytmu
  const handleAlgorithmChange = (algorithmId: string) => {
    setSelectedAlgorithm(algorithmId);
    setKey(getDefaultKey(algorithmId));
    setError('');
    setOutputText('');
    // Dla SHA-256 zawsze ustawiamy operację na 'encrypt' (haszowanie)
    // Dla digital-signature zawsze ustawiamy na 'encrypt' (podpisywanie)
    if (algorithmId === 'sha256' || algorithmId === 'digital-signature') {
      setOperation('encrypt');
    }
  };

  const handleProcess = () => {
    setError('');

    if (!inputText.trim()) {
      setError('Wprowadź tekst do przetworzenia');
      return;
    }

    if (!currentAlgo) {
      setError('Nie znaleziono wybranego algorytmu');
      return;
    }

    // Jeśli to AES, ustaw wybrany tryb
    if (selectedAlgorithm === 'aes' && currentAlgo instanceof AESCipher) {
      currentAlgo.setMode(aesMode);
    }

    const validation = currentAlgo.validateKey(key);
    if (!validation.valid) {
      setError(validation.error || 'Nieprawidłowy klucz');
      return;
    }

    try {
      // Rozpocznij logowanie operacji
      logManager.startOperation();
      
      const startTime = Date.now();
      // Dla SHA-256 zawsze wywołujemy encrypt (generowanie hasha)
      // Dla digital-signature zawsze encrypt (podpisywanie) lub decrypt (weryfikacja)
      let effectiveOperation = operation;
      if (selectedAlgorithm === 'sha256') {
        effectiveOperation = 'encrypt';
      }
      const result =
        effectiveOperation === 'encrypt'
          ? currentAlgo.encrypt(inputText, key)
          : currentAlgo.decrypt(inputText, key);
      const duration = Date.now() - startTime;
      
      setOutputText(result);
      
      // Zapisz log operacji
      logManager.finishOperation(
        selectedAlgorithm,
        currentAlgo.name,
        operation,
        inputText,
        result,
        key,
        true,
        undefined,
        selectedAlgorithm === 'aes' ? aesMode : undefined
      );
      
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Nieznany błąd';
      setError('Błąd podczas przetwarzania: ' + errorMessage);
      
      // Zapisz log błędu
      logManager.finishOperation(
        selectedAlgorithm,
        currentAlgo.name,
        operation,
        inputText,
        '',
        key,
        false,
        errorMessage,
        selectedAlgorithm === 'aes' ? aesMode : undefined
      );
    }
  };

  const handleFileUpload = async () => {
    try {
      const content = await pickTextFile();
      if (content) {
        setInputText(content);
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Nieznany błąd';
      Alert.alert('Błąd', errorMessage);
    }
  };

  const handleCopyToClipboard = async () => {
    if (!outputText) {
      Alert.alert('Błąd', 'Brak tekstu do skopiowania');
      return;
    }

    try {
      await Clipboard.setStringAsync(outputText);
      Alert.alert('Sukces', 'Tekst skopiowany do schowka!');
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Nieznany błąd';
      Alert.alert('Błąd', `Nie udało się skopiować: ${errorMessage}`);
    }
  };

  const handleDownload = async () => {
    if (!outputText) {
      Alert.alert('Błąd', 'Brak tekstu do zapisania');
      return;
    }

    try {
      const filename = `${operation}_${selectedAlgorithm}_${Date.now()}.txt`;
      await saveTextFile(outputText, filename);
      Alert.alert(
        'Plik gotowy', 
        'Plik został utworzony. Wybierz "Zapisz do plików" aby zachować go na urządzeniu.',
        [{ text: 'OK' }]
      );
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Nieznany błąd';
      Alert.alert('Błąd', errorMessage);
    }
  };

  const handleGenerateRSAKeys = () => {
    try {
      const rsa = new RSACipher();
      const keyPair = rsa.generateKeyPair();
      const publicKey = rsa.formatPublicKey();
      const privateKey = rsa.formatPrivateKey();
      
      setRsaPublicKey(publicKey);
      setRsaPrivateKey(privateKey);
      setShowRSAKeysModal(true);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Nieznany błąd';
      Alert.alert('Błąd', 'Nie udało się wygenerować kluczy: ' + errorMessage);
    }
  };

  const handleGenerateECDHKeys = () => {
    try {
      const ecdh = new ECDHAlgorithm();
      const keyPair = ecdh.generateKeyPair();
      
      setRsaPublicKey(keyPair.publicKey);
      setRsaPrivateKey(keyPair.privateKey);
      setShowRSAKeysModal(true);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Nieznany błąd';
      Alert.alert('Błąd', 'Nie udało się wygenerować kluczy: ' + errorMessage);
    }
  };

  const handleGenerateElGamalKeys = () => {
    try {
      const elgamal = new ElGamalCipher();
      const keyPair = elgamal.generateKeyPair();
      
      // Formatowanie kluczy do wyświetlenia
      const pubKey = `${keyPair.publicKey.p},${keyPair.publicKey.g},${keyPair.publicKey.y}`;
      const privKey = `${keyPair.privateKey.x},${keyPair.privateKey.p}`;

      setRsaPublicKey(pubKey);
      setRsaPrivateKey(privKey);
      setShowRSAKeysModal(true);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Nieznany błąd';
      Alert.alert('Błąd', 'Nie udało się wygenerować kluczy: ' + errorMessage);
    }
  };

  const handleCopyRSAKey = async (keyType: 'public' | 'private') => {
    const keyToCopy = keyType === 'public' ? rsaPublicKey : rsaPrivateKey;
    try {
      await Clipboard.setStringAsync(keyToCopy);
      Alert.alert('Sukces', `Klucz ${keyType === 'public' ? 'publiczny' : 'prywatny'} skopiowany do schowka!`);
    } catch (err) {
      Alert.alert('Błąd', 'Nie udało się skopiować klucza');
    }
  };

  const handleUseRSAKey = (keyType: 'public' | 'private') => {
    const keyToUse = keyType === 'public' ? rsaPublicKey : rsaPrivateKey;
    setKey(keyToUse);
    setShowRSAKeysModal(false);
    Alert.alert('Sukces', `Klucz ${keyType === 'public' ? 'publiczny' : 'prywatny'} został ustawiony`);
  };

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar style="light" />

      {/* Header */}
      <View style={styles.header}>
        <View style={styles.headerLeft}>
          <MaterialIcons name="lock" size={32} color="#a78bfa" />
          <View>
            <Text style={styles.headerTitle}>CryptoLab</Text>
            <Text style={styles.headerSubtitle}>Platforma do nauki kryptografii</Text>
          </View>
        </View>
        <View style={styles.headerRight}>
          <TouchableOpacity
            style={styles.iconButton}
            onPress={() => setShowDocs(!showDocs)}
          >
            <MaterialIcons name="book" size={24} color="#fff" />
          </TouchableOpacity>
          <TouchableOpacity
            style={styles.iconButton}
            onPress={() => setShowSidebar(!showSidebar)}
          >
            <MaterialIcons name="menu" size={24} color="#fff" />
          </TouchableOpacity>
        </View>
      </View>

      {/* Navigation Tabs */}
      <View style={styles.navigationTabs}>
        <TouchableOpacity
          style={[styles.navTab, currentView === 'crypto' && styles.navTabActive]}
          onPress={() => setCurrentView('crypto')}
        >
          <MaterialIcons
            name="lock"
            size={20}
            color={currentView === 'crypto' ? '#a78bfa' : '#94a3b8'}
          />
          <Text
            style={[
              styles.navTabText,
              currentView === 'crypto' && styles.navTabTextActive,
            ]}
          >
            Szyfrowanie
          </Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.navTab, currentView === 'logs' && styles.navTabActive]}
          onPress={() => setCurrentView('logs')}
        >
          <MaterialIcons
            name="history"
            size={20}
            color={currentView === 'logs' ? '#a78bfa' : '#94a3b8'}
          />
          <Text
            style={[
              styles.navTabText,
              currentView === 'logs' && styles.navTabTextActive,
            ]}
          >
            Logi
          </Text>
        </TouchableOpacity>
      </View>

      {/* Conditional Content */}
      {currentView === 'logs' ? (
        <LogsViewer />
      ) : (
      <KeyboardAvoidingView
        behavior={Platform.OS === 'ios' ? 'padding' : undefined}
        style={styles.keyboardAvoidingView}
        keyboardVerticalOffset={Platform.OS === 'ios' ? 90 : 0}
      >
        <TouchableWithoutFeedback onPress={Keyboard.dismiss}>
          <ScrollView 
            style={styles.content}
            contentContainerStyle={styles.contentContainer}
            keyboardShouldPersistTaps="handled"
            showsVerticalScrollIndicator={false}
          >
        {/* Algorithm Info */}
        <View style={styles.infoCard}>
          <View style={styles.infoHeader}>
            <MaterialIcons name="info" size={24} color="#a78bfa" />
            <View style={styles.infoTextContainer}>
              <Text style={styles.infoTitle}>{currentAlgo?.name}</Text>
              <Text style={styles.infoDescription}>{currentAlgo?.description}</Text>
              <Text style={styles.infoRequirements}>
                <Text style={styles.infoLabel}>Wymagany klucz: </Text>
                {currentAlgo?.getKeyRequirements()}
              </Text>
            </View>
          </View>
        </View>

        {/* Controls */}
        <View style={styles.card}>
          {/* Mode Selection */}
          <View style={styles.section}>
            <Text style={styles.label}>Tryb pracy</Text>
            <View style={styles.buttonGroup}>
              <TouchableOpacity
                style={[styles.modeButton, mode === 'text' && styles.modeButtonActive]}
                onPress={() => setMode('text')}
              >
                <MaterialIcons
                  name="text-fields"
                  size={16}
                  color={mode === 'text' ? '#fff' : '#cbd5e1'}
                />
                <Text
                  style={[
                    styles.modeButtonText,
                    mode === 'text' && styles.modeButtonTextActive,
                  ]}
                >
                  Tekst
                </Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.modeButton, mode === 'file' && styles.modeButtonActive]}
                onPress={() => setMode('file')}
              >
                <MaterialIcons
                  name="upload-file"
                  size={16}
                  color={mode === 'file' ? '#fff' : '#cbd5e1'}
                />
                <Text
                  style={[
                    styles.modeButtonText,
                    mode === 'file' && styles.modeButtonTextActive,
                  ]}
                >
                  Plik
                </Text>
              </TouchableOpacity>
            </View>
          </View>

          {/* Operation Selection */}
          <View style={styles.section}>
            <Text style={styles.label}>Operacja</Text>
            {selectedAlgorithm === 'sha256' ? (
              // Dla SHA-256 tylko jedna opcja - haszowanie
              <View style={styles.buttonGroup}>
                <TouchableOpacity
                  style={[styles.operationButton, styles.operationButtonEncrypt]}
                  disabled
                >
                  <Text style={[styles.operationButtonText, styles.operationButtonTextActive]}>
                    Haszuj
                  </Text>
                </TouchableOpacity>
              </View>
            ) : selectedAlgorithm === 'digital-signature' ? (
              // Dla podpisu elektronicznego - Podpisz i Weryfikuj
              <View style={styles.buttonGroup}>
                <TouchableOpacity
                  style={[
                    styles.operationButton,
                    operation === 'encrypt' && styles.operationButtonEncrypt,
                  ]}
                  onPress={() => setOperation('encrypt')}
                >
                  <Text
                    style={[
                      styles.operationButtonText,
                      operation === 'encrypt' && styles.operationButtonTextActive,
                    ]}
                  >
                    Podpisz
                  </Text>
                </TouchableOpacity>
                <TouchableOpacity
                  style={[
                    styles.operationButton,
                    operation === 'decrypt' && styles.operationButtonDecrypt,
                  ]}
                  onPress={() => setOperation('decrypt')}
                >
                  <Text
                    style={[
                      styles.operationButtonText,
                      operation === 'decrypt' && styles.operationButtonTextActive,
                    ]}
                  >
                    Weryfikuj
                  </Text>
                </TouchableOpacity>
              </View>
            ) : (
              // Dla innych algorytmów standardowe przyciski
              <View style={styles.buttonGroup}>
                <TouchableOpacity
                  style={[
                    styles.operationButton,
                    operation === 'encrypt' && styles.operationButtonEncrypt,
                  ]}
                  onPress={() => setOperation('encrypt')}
                >
                  <Text
                    style={[
                      styles.operationButtonText,
                      operation === 'encrypt' && styles.operationButtonTextActive,
                    ]}
                  >
                    Szyfruj
                  </Text>
                </TouchableOpacity>
                <TouchableOpacity
                  style={[
                    styles.operationButton,
                    operation === 'decrypt' && styles.operationButtonDecrypt,
                  ]}
                  onPress={() => setOperation('decrypt')}
                >
                  <Text
                    style={[
                      styles.operationButtonText,
                      operation === 'decrypt' && styles.operationButtonTextActive,
                    ]}
                  >
                    Deszyfruj
                  </Text>
                </TouchableOpacity>
              </View>
            )}
          </View>

          {/* AES Mode Selection - pokaż tylko dla AES */}
          {selectedAlgorithm === 'aes' && (
            <View style={styles.section}>
              <Text style={styles.label}>Tryb AES</Text>
              <View style={styles.buttonGroup}>
                <TouchableOpacity
                  style={[
                    styles.aesModeButton,
                    aesMode === 'ECB' && styles.aesModeButtonActive,
                  ]}
                  onPress={() => setAesMode('ECB')}
                >
                  <Text
                    style={[
                      styles.aesModeButtonText,
                      aesMode === 'ECB' && styles.aesModeButtonTextActive,
                    ]}
                  >
                    ECB
                  </Text>
                </TouchableOpacity>
                <TouchableOpacity
                  style={[
                    styles.aesModeButton,
                    aesMode === 'CBC' && styles.aesModeButtonActive,
                  ]}
                  onPress={() => setAesMode('CBC')}
                >
                  <Text
                    style={[
                      styles.aesModeButtonText,
                      aesMode === 'CBC' && styles.aesModeButtonTextActive,
                    ]}
                  >
                    CBC
                  </Text>
                </TouchableOpacity>
                <TouchableOpacity
                  style={[
                    styles.aesModeButton,
                    aesMode === 'CTR' && styles.aesModeButtonActive,
                  ]}
                  onPress={() => setAesMode('CTR')}
                >
                  <Text
                    style={[
                      styles.aesModeButtonText,
                      aesMode === 'CTR' && styles.aesModeButtonTextActive,
                    ]}
                  >
                    CTR
                  </Text>
                </TouchableOpacity>
              </View>
            </View>
          )}

          {/* Key Input - ukryj dla Running Key Cipher */}
          {selectedAlgorithm !== 'running-key' && selectedAlgorithm !== 'sha256' && selectedAlgorithm !== 'digital-signature' && (
            <View style={styles.section}>
              <View style={styles.labelWithButton}>
                <Text style={styles.label}>Klucz</Text>
                {(selectedAlgorithm === 'rsa' || selectedAlgorithm === 'ecdh' || selectedAlgorithm === 'elgamal') && (
                  <TouchableOpacity 
                    style={styles.generateKeysButton}
                    onPress={() => {
                      if (selectedAlgorithm === 'rsa') handleGenerateRSAKeys();
                      else if (selectedAlgorithm === 'ecdh') handleGenerateECDHKeys();
                      else if (selectedAlgorithm === 'elgamal') handleGenerateElGamalKeys();
                    }}
                  >
                    <MaterialIcons name="vpn-key" size={16} color="#fff" />
                    <Text style={styles.generateKeysButtonText}>Generuj klucze</Text>
                  </TouchableOpacity>
                )}
              </View>
              <TextInput
                style={styles.input}
                value={key}
                onChangeText={setKey}
                placeholder="Wprowadź klucz"
                placeholderTextColor="#64748b"
              />
            </View>
          )}

          {/* File Upload */}
          {mode === 'file' && (
            <TouchableOpacity style={styles.fileUploadButton} onPress={handleFileUpload}>
              <MaterialIcons name="upload-file" size={24} color="#a78bfa" />
              <Text style={styles.fileUploadText}>Wybierz plik tekstowy</Text>
            </TouchableOpacity>
          )}

          {/* Input Text */}
          <View style={styles.section}>
            <Text style={styles.label}>Tekst wejściowy</Text>
            <TextInput
              style={styles.textArea}
              value={inputText}
              onChangeText={setInputText}
              placeholder="Wprowadź tekst do przetworzenia..."
              placeholderTextColor="#64748b"
              multiline
              numberOfLines={5}
              textAlignVertical="top"
            />
          </View>

          {/* Process Button */}
          <TouchableOpacity style={styles.processButton} onPress={handleProcess}>
            <Text style={styles.processButtonText}>
              {selectedAlgorithm === 'sha256' 
                ? 'Wygeneruj hash'
                : selectedAlgorithm === 'digital-signature'
                ? (operation === 'encrypt' ? 'Podpisz dokument' : 'Weryfikuj podpis')
                : (operation === 'encrypt' ? 'Zaszyfruj' : 'Odszyfruj')}
            </Text>
          </TouchableOpacity>

          {/* Error */}
          {error !== '' && (
            <View style={styles.errorCard}>
              <Text style={styles.errorText}>{error}</Text>
            </View>
          )}

          {/* Output */}
          {outputText !== '' && (
            <View style={styles.section}>
              <View style={styles.outputHeader}>
                <Text style={styles.label}>
                  {selectedAlgorithm === 'sha256' 
                    ? 'Hash SHA-256'
                    : selectedAlgorithm === 'digital-signature'
                    ? (operation === 'encrypt' ? 'Podpis elektroniczny' : 'Wynik weryfikacji')
                    : 'Wynik'}
                </Text>
                <View style={styles.outputActions}>
                  <TouchableOpacity 
                    style={styles.actionButton} 
                    onPress={handleCopyToClipboard}
                  >
                    <MaterialIcons name="content-copy" size={16} color="#fff" />
                    <Text style={styles.actionButtonText}>Kopiuj</Text>
                  </TouchableOpacity>
                  <TouchableOpacity 
                    style={styles.actionButton} 
                    onPress={handleDownload}
                  >
                    <MaterialIcons name="download" size={16} color="#fff" />
                    <Text style={styles.actionButtonText}>Pobierz</Text>
                  </TouchableOpacity>
                </View>
              </View>
              {/* Info for Running Key Cipher */}
              {selectedAlgorithm === 'running-key' && (
                <View style={{ marginBottom: 8 }}>
                  <Text style={{ color: '#a78bfa', fontSize: 13 }}>
                    Wynik zawiera klucz oraz zaszyfrowany tekst w formacie:
                  </Text>
                  <Text style={{ color: '#cbd5e1', fontSize: 13 }}>
                    {'<klucz>::<zaszyfrowany_tekst>'}
                  </Text>
                  <Text style={{ color: '#94a3b8', fontSize: 12 }}>
                    Klucz to fragment przed dwukropkiem (::), szyfr po dwukropku.
                  </Text>
                </View>
              )}
              {/* Info for SHA-256 Hash */}
              {selectedAlgorithm === 'sha256' && (
                <View style={{ marginBottom: 8, backgroundColor: 'rgba(167, 139, 250, 0.1)', padding: 12, borderRadius: 8, borderLeftWidth: 3, borderLeftColor: '#a78bfa' }}>
                  <Text style={{ color: '#a78bfa', fontSize: 13, fontWeight: '600', marginBottom: 4 }}>
                    ℹ️ Funkcja jednokierunkowa
                  </Text>
                  <Text style={{ color: '#cbd5e1', fontSize: 12 }}>
                    SHA-256 to funkcja skrótu (hash), nie szyfr. Generuje 256-bitowy odcisk cyfrowy tekstu.
                  </Text>
                  <Text style={{ color: '#94a3b8', fontSize: 11, marginTop: 4 }}>
                    ⚠️ Nie można odwrócić - "Deszyfruj" nie jest dostępne dla funkcji skrótu.
                  </Text>
                </View>
              )}
              {/* Info for Digital Signature */}
              {selectedAlgorithm === 'digital-signature' && (
                <View style={{ marginBottom: 8, backgroundColor: 'rgba(34, 197, 94, 0.1)', padding: 12, borderRadius: 8, borderLeftWidth: 3, borderLeftColor: '#22c55e' }}>
                  <Text style={{ color: '#22c55e', fontSize: 13, fontWeight: '600', marginBottom: 4 }}>
                    🔐 Podpis Elektroniczny (RSA-SHA256)
                  </Text>
                  <Text style={{ color: '#cbd5e1', fontSize: 12 }}>
                    Podpis łączy SHA-256 z RSA do autentykacji dokumentów. Format: dokument|hash|podpis|klucz_publiczny
                  </Text>
                  <Text style={{ color: '#94a3b8', fontSize: 11, marginTop: 4 }}>
                    💡 Podpisz dokument, a następnie skopiuj CAŁY wynik i wklej do weryfikacji.
                  </Text>
                </View>
              )}
              <TextInput
                style={[styles.textArea, styles.outputTextArea]}
                value={outputText}
                editable={false}
                multiline
                numberOfLines={5}
                textAlignVertical="top"
              />
            </View>
          )}
        </View>
          </ScrollView>
        </TouchableWithoutFeedback>
      </KeyboardAvoidingView>
      )}

      {/* Sidebar Modal */}
      <Modal
        visible={showSidebar}
        transparent
        animationType="slide"
        onRequestClose={() => setShowSidebar(false)}
      >
        <View style={styles.modalOverlay}>
          <View style={styles.modalContent}>
            <View style={styles.modalHeader}>
              <Text style={styles.modalTitle}>Wybierz algorytm</Text>
              <TouchableOpacity onPress={() => setShowSidebar(false)}>
                <MaterialIcons name="close" size={24} color="#fff" />
              </TouchableOpacity>
            </View>
            <ScrollView>
              <AlgorithmSidebar
                algorithms={algorithms}
                selectedAlgorithm={selectedAlgorithm}
                onSelectAlgorithm={(id) => {
                  handleAlgorithmChange(id);
                  setShowSidebar(false);
                }}
              />
            </ScrollView>
          </View>
        </View>
      </Modal>

      {/* RSA Keys Generator Modal */}
      <Modal
        visible={showRSAKeysModal}
        transparent
        animationType="slide"
        onRequestClose={() => setShowRSAKeysModal(false)}
      >
        <View style={styles.modalOverlay}>
          <View style={styles.modalContent}>
            <View style={styles.modalHeader}>
              <Text style={styles.modalTitle}>
                {selectedAlgorithm === 'ecdh' ? 'Wygenerowane klucze ECDH' : 
                 selectedAlgorithm === 'elgamal' ? 'Wygenerowane klucze ElGamal' : 
                 'Wygenerowane klucze RSA'}
              </Text>
              <TouchableOpacity onPress={() => setShowRSAKeysModal(false)}>
                <MaterialIcons name="close" size={24} color="#fff" />
              </TouchableOpacity>
            </View>
            <ScrollView style={styles.rsaKeysContent}>
              <View style={styles.rsaKeySection}>
                <Text style={styles.rsaKeyLabel}>Klucz publiczny (do szyfrowania):</Text>
                <View style={styles.rsaKeyBox}>
                  <Text style={styles.rsaKeyText} selectable>{rsaPublicKey}</Text>
                </View>
                <View style={styles.rsaKeyActions}>
                  <TouchableOpacity 
                    style={styles.rsaKeyButton}
                    onPress={() => handleCopyRSAKey('public')}
                  >
                    <MaterialIcons name="content-copy" size={16} color="#fff" />
                    <Text style={styles.rsaKeyButtonText}>Kopiuj</Text>
                  </TouchableOpacity>
                  <TouchableOpacity 
                    style={[styles.rsaKeyButton, styles.rsaKeyButtonPrimary]}
                    onPress={() => handleUseRSAKey('public')}
                  >
                    <MaterialIcons name="check" size={16} color="#fff" />
                    <Text style={styles.rsaKeyButtonText}>Użyj tego klucza</Text>
                  </TouchableOpacity>
                </View>
              </View>

              <View style={styles.rsaKeySection}>
                <Text style={styles.rsaKeyLabel}>Klucz prywatny (do deszyfrowania):</Text>
                <View style={styles.rsaKeyBox}>
                  <Text style={styles.rsaKeyText} selectable>{rsaPrivateKey}</Text>
                </View>
                <View style={styles.rsaKeyActions}>
                  <TouchableOpacity 
                    style={styles.rsaKeyButton}
                    onPress={() => handleCopyRSAKey('private')}
                  >
                    <MaterialIcons name="content-copy" size={16} color="#fff" />
                    <Text style={styles.rsaKeyButtonText}>Kopiuj</Text>
                  </TouchableOpacity>
                  <TouchableOpacity 
                    style={[styles.rsaKeyButton, styles.rsaKeyButtonPrimary]}
                    onPress={() => handleUseRSAKey('private')}
                  >
                    <MaterialIcons name="check" size={16} color="#fff" />
                    <Text style={styles.rsaKeyButtonText}>Użyj tego klucza</Text>
                  </TouchableOpacity>
                </View>
              </View>

              <View style={styles.rsaKeyInfo}>
                <MaterialIcons name="info" size={20} color="#a78bfa" />
                <Text style={styles.rsaKeyInfoText}>
                  Zapisz oba klucze! Klucz publiczny służy do szyfrowania, 
                  a klucz prywatny do deszyfrowania wiadomości.
                </Text>
              </View>
            </ScrollView>
          </View>
        </View>
      </Modal>

      {/* Documentation Modal */}
      <Modal
        visible={showDocs}
        transparent
        animationType="slide"
        onRequestClose={() => setShowDocs(false)}
      >
        <View style={styles.modalOverlay}>
          <View style={styles.modalContent}>
            <View style={styles.modalHeader}>
              <Text style={styles.modalTitle}>Dokumentacja projektowa</Text>
              <TouchableOpacity onPress={() => setShowDocs(false)}>
                <MaterialIcons name="close" size={24} color="#fff" />
              </TouchableOpacity>
            </View>
            <ScrollView style={styles.docsContent}>
              <View style={styles.docsSection}>
                <Text style={styles.docsHeading}>1. Architektura aplikacji</Text>
                <View style={styles.docsBox}>
                  <Text style={styles.docsText}>
                    <Text style={styles.docsBold}>Wzorzec projektowy:</Text> Strategy
                    Pattern
                  </Text>
                  <Text style={styles.docsText}>
                    <Text style={styles.docsBold}>Implementacja:</Text> Wszystkie algorytmy
                    są implementowane ręcznie, bez gotowych bibliotek kryptograficznych
                  </Text>
                </View>
              </View>

              <View style={styles.docsSection}>
                <Text style={styles.docsHeading}>2. Szyfr Cezara</Text>
                <View style={styles.docsBox}>
                  <Text style={styles.docsBold}>Historia:</Text>
                  <Text style={styles.docsText}>
                    Szyfr nazwany na cześć Juliusza Cezara, który używał go do komunikacji
                    wojskowej około 58 r. p.n.e.
                  </Text>
                  <Text style={[styles.docsBold, styles.docsMarginTop]}>
                    Wzory matematyczne:
                  </Text>
                  <View style={styles.docsCode}>
                    <Text style={styles.docsCodeText}>E(x) = (x + k) mod 26</Text>
                    <Text style={styles.docsCodeText}>D(x) = (x - k) mod 26</Text>
                  </View>
                  <Text style={[styles.docsText, styles.docsMarginTop]}>
                    gdzie x to pozycja litery w alfabecie (0-25), k to wartość przesunięcia
                  </Text>
                </View>
              </View>

              <View style={styles.docsSection}>
                <Text style={styles.docsHeading}>3. Szyfr Vigenère'a</Text>
                <View style={styles.docsBox}>
                  <Text style={styles.docsBold}>Historia:</Text>
                  <Text style={styles.docsText}>
                    Opracowany przez Blaise'a de Vigenère w XVI wieku. Przez wieki uważany
                    za "szyfr nie do złamania" (le chiffre indéchiffrable). Łamany dopiero
                    w XIX wieku przez Charlesa Babbage'a i Friedricha Kasiskiego.
                  </Text>
                  <Text style={[styles.docsBold, styles.docsMarginTop]}>
                    Zasada działania:
                  </Text>
                  <Text style={styles.docsText}>
                    Szyfr polialfabetyczny używający słowa klucza powtarzanego w cyklu.
                    Każda litera klucza określa przesunięcie dla odpowiedniej litery tekstu.
                  </Text>
                  <Text style={[styles.docsBold, styles.docsMarginTop]}>
                    Wzory matematyczne:
                  </Text>
                  <View style={styles.docsCode}>
                    <Text style={styles.docsCodeText}>E(x,k) = (x + k) mod 26</Text>
                    <Text style={styles.docsCodeText}>D(x,k) = (x - k) mod 26</Text>
                  </View>
                  <Text style={[styles.docsText, styles.docsMarginTop]}>
                    gdzie x to litera tekstu jawnego, k to kolejna litera klucza
                  </Text>
                  <Text style={[styles.docsBold, styles.docsMarginTop]}>
                    Przykład:
                  </Text>
                  <Text style={styles.docsText}>
                    Tekst: ATTACKATDAWN{'\n'}
                    Klucz: LEMONLEMONLE{'\n'}
                    Wynik: LXFOPVEFRNHR
                  </Text>
                </View>
              </View>

              <View style={styles.docsSection}>
                <Text style={styles.docsHeading}>4. Szyfr z kluczem bieżącym</Text>
                <View style={styles.docsBox}>
                  <Text style={styles.docsBold}>Historia:</Text>
                  <Text style={styles.docsText}>
                    Rozwinięcie szyfru Vigenère'a. Zamiast krótkiego słowa klucza używa
                    długiego tekstu (np. fragmentu książki) jako klucza. Teoretycznie
                    bezpieczniejszy od Vigenère'a przy losowym kluczu jednorazowym.
                  </Text>
                  <Text style={[styles.docsBold, styles.docsMarginTop]}>
                    Zasada działania:
                  </Text>
                  <Text style={styles.docsText}>
                    Identyczna jak Vigenère, ale klucz ma tę samą długość co tekst jawny
                    i nie jest powtarzany. Idealnie - klucz powinien być całkowicie losowy
                    i używany tylko raz (One-Time Pad).
                  </Text>
                  <Text style={[styles.docsBold, styles.docsMarginTop]}>
                    Wzory matematyczne:
                  </Text>
                  <View style={styles.docsCode}>
                    <Text style={styles.docsCodeText}>E(x,k) = (x + k) mod 26</Text>
                    <Text style={styles.docsCodeText}>D(x,k) = (x - k) mod 26</Text>
                  </View>
                  <Text style={[styles.docsText, styles.docsMarginTop]}>
                    gdzie długość klucza k ≥ długość tekstu x
                  </Text>
                  <Text style={[styles.docsBold, styles.docsMarginTop]}>
                    Uwaga bezpieczeństwa:
                  </Text>
                  <Text style={styles.docsText}>
                    Klucz musi być:{'\n'}
                    • Prawdziwie losowy{'\n'}
                    • Używany tylko raz{'\n'}
                    • Co najmniej tak długi jak tekst{'\n'}
                    • Znany tylko nadawcy i odbiorcy
                  </Text>
                </View>
              </View>
            </ScrollView>
          </View>
        </View>
      </Modal>
    </SafeAreaView>
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
    backgroundColor: 'rgba(0, 0, 0, 0.3)',
    borderBottomWidth: 1,
    borderBottomColor: 'rgba(147, 51, 234, 0.3)',
  },
  headerLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  headerTitle: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#fff',
  },
  headerSubtitle: {
    fontSize: 12,
    color: '#a78bfa',
  },
  headerRight: {
    flexDirection: 'row',
    gap: 8,
  },
  iconButton: {
    padding: 8,
    borderRadius: 8,
  },
  navigationTabs: {
    flexDirection: 'row',
    backgroundColor: '#1e293b',
    borderBottomWidth: 1,
    borderBottomColor: '#334155',
  },
  navTab: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
    paddingVertical: 16,
    borderBottomWidth: 2,
    borderBottomColor: 'transparent',
  },
  navTabActive: {
    borderBottomColor: '#a78bfa',
    backgroundColor: '#0f172a',
  },
  navTabText: {
    fontSize: 14,
    fontWeight: '600',
    color: '#94a3b8',
  },
  navTabTextActive: {
    color: '#a78bfa',
  },
  keyboardAvoidingView: {
    flex: 1,
  },
  content: {
    flex: 1,
    padding: 16,
  },
  contentContainer: {
    paddingBottom: 20,
  },
  infoCard: {
    backgroundColor: 'rgba(88, 28, 135, 0.4)',
    borderRadius: 12,
    padding: 16,
    marginBottom: 16,
    borderWidth: 1,
    borderColor: 'rgba(147, 51, 234, 0.3)',
  },
  infoHeader: {
    flexDirection: 'row',
    gap: 12,
  },
  infoTextContainer: {
    flex: 1,
  },
  infoTitle: {
    fontSize: 20,
    fontWeight: '600',
    color: '#fff',
    marginBottom: 8,
  },
  infoDescription: {
    fontSize: 14,
    color: '#cbd5e1',
    marginBottom: 12,
  },
  infoRequirements: {
    fontSize: 12,
    color: '#94a3b8',
  },
  infoLabel: {
    fontWeight: 'bold',
  },
  card: {
    backgroundColor: 'rgba(0, 0, 0, 0.3)',
    borderRadius: 12,
    padding: 16,
    borderWidth: 1,
    borderColor: 'rgba(147, 51, 234, 0.3)',
  },
  section: {
    marginBottom: 16,
  },
  label: {
    fontSize: 14,
    fontWeight: '500',
    color: '#fff',
    marginBottom: 8,
  },
  buttonGroup: {
    flexDirection: 'row',
    gap: 8,
  },
  modeButton: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
    paddingVertical: 12,
    paddingHorizontal: 16,
    borderRadius: 8,
    backgroundColor: '#334155',
  },
  modeButtonActive: {
    backgroundColor: '#9333ea',
  },
  modeButtonText: {
    fontSize: 14,
    color: '#cbd5e1',
  },
  modeButtonTextActive: {
    color: '#fff',
  },
  operationButton: {
    flex: 1,
    paddingVertical: 12,
    paddingHorizontal: 16,
    borderRadius: 8,
    backgroundColor: '#334155',
    alignItems: 'center',
  },
  operationButtonEncrypt: {
    backgroundColor: '#16a34a',
  },
  operationButtonDecrypt: {
    backgroundColor: '#dc2626',
  },
  operationButtonText: {
    fontSize: 14,
    color: '#cbd5e1',
  },
  operationButtonTextActive: {
    color: '#fff',
  },
  aesModeButton: {
    flex: 1,
    paddingVertical: 10,
    paddingHorizontal: 12,
    borderRadius: 8,
    backgroundColor: '#334155',
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#475569',
  },
  aesModeButtonActive: {
    backgroundColor: '#7c3aed',
    borderColor: '#a78bfa',
  },
  aesModeButtonText: {
    fontSize: 13,
    color: '#cbd5e1',
    fontWeight: '500',
  },
  aesModeButtonTextActive: {
    color: '#fff',
  },
  input: {
    backgroundColor: '#334155',
    borderWidth: 1,
    borderColor: '#475569',
    borderRadius: 8,
    padding: 12,
    color: '#fff',
    fontSize: 14,
  },
  textArea: {
    backgroundColor: '#334155',
    borderWidth: 1,
    borderColor: '#475569',
    borderRadius: 8,
    padding: 12,
    color: '#fff',
    fontSize: 14,
    minHeight: 120,
    fontFamily: 'monospace',
  },
  outputTextArea: {
    backgroundColor: '#1e293b',
    color: '#4ade80',
  },
  fileUploadButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
    padding: 16,
    borderRadius: 8,
    borderWidth: 2,
    borderStyle: 'dashed',
    borderColor: '#475569',
    backgroundColor: '#334155',
    marginBottom: 16,
  },
  fileUploadText: {
    color: '#cbd5e1',
    fontSize: 14,
  },
  processButton: {
    backgroundColor: '#9333ea',
    paddingVertical: 16,
    borderRadius: 8,
    alignItems: 'center',
    marginBottom: 16,
  },
  processButtonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  errorCard: {
    backgroundColor: 'rgba(220, 38, 38, 0.5)',
    borderWidth: 1,
    borderColor: '#ef4444',
    borderRadius: 8,
    padding: 12,
    marginBottom: 16,
  },
  errorText: {
    color: '#fecaca',
    fontSize: 14,
  },
  outputHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  outputActions: {
    flexDirection: 'row',
    gap: 8,
  },
  actionButton: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
    paddingVertical: 6,
    paddingHorizontal: 12,
    borderRadius: 6,
    backgroundColor: '#334155',
  },
  actionButtonText: {
    color: '#fff',
    fontSize: 12,
  },
  downloadButton: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
    paddingVertical: 6,
    paddingHorizontal: 12,
    borderRadius: 6,
    backgroundColor: '#334155',
  },
  downloadButtonText: {
    color: '#fff',
    fontSize: 12,
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
    maxHeight: '80%',
    padding: 16,
  },
  modalHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 16,
  },
  modalTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    color: '#fff',
  },
  docsContent: {
    flex: 1,
  },
  docsSection: {
    marginBottom: 24,
  },
  docsHeading: {
    fontSize: 18,
    fontWeight: '600',
    color: '#a78bfa',
    marginBottom: 12,
  },
  docsBox: {
    backgroundColor: 'rgba(30, 41, 59, 0.5)',
    padding: 16,
    borderRadius: 8,
  },
  docsText: {
    color: '#cbd5e1',
    fontSize: 14,
    marginBottom: 8,
  },
  docsBold: {
    color: '#a78bfa',
    fontWeight: '600',
  },
  docsMarginTop: {
    marginTop: 12,
  },
  docsCode: {
    backgroundColor: '#0f172a',
    padding: 12,
    borderRadius: 6,
    marginTop: 8,
  },
  docsCodeText: {
    color: '#cbd5e1',
    fontFamily: 'monospace',
    fontSize: 12,
  },
  // RSA Keys Generator styles
  labelWithButton: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  generateKeysButton: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#a78bfa',
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 6,
    gap: 4,
  },
  generateKeysButtonText: {
    color: '#fff',
    fontSize: 12,
    fontWeight: '600',
  },
  rsaKeysContent: {
    padding: 20,
  },
  rsaKeySection: {
    marginBottom: 24,
  },
  rsaKeyLabel: {
    color: '#e2e8f0',
    fontSize: 14,
    fontWeight: '600',
    marginBottom: 8,
  },
  rsaKeyBox: {
    backgroundColor: '#0f172a',
    padding: 12,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: '#334155',
    marginBottom: 12,
  },
  rsaKeyText: {
    color: '#a78bfa',
    fontSize: 13,
    fontFamily: 'monospace',
  },
  rsaKeyActions: {
    flexDirection: 'row',
    gap: 8,
  },
  rsaKeyButton: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#334155',
    paddingVertical: 10,
    paddingHorizontal: 12,
    borderRadius: 8,
    gap: 6,
  },
  rsaKeyButtonPrimary: {
    backgroundColor: '#a78bfa',
  },
  rsaKeyButtonText: {
    color: '#fff',
    fontSize: 13,
    fontWeight: '600',
  },
  rsaKeyInfo: {
    flexDirection: 'row',
    gap: 10,
    backgroundColor: '#1e293b',
    padding: 12,
    borderRadius: 8,
    borderLeftWidth: 3,
    borderLeftColor: '#a78bfa',
    marginTop: 8,
  },
  rsaKeyInfoText: {
    flex: 1,
    color: '#cbd5e1',
    fontSize: 13,
    lineHeight: 18,
  },
});
