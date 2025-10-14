import React from 'react';
import { View, Text, StyleSheet, TouchableOpacity, ScrollView } from 'react-native';
import { MaterialIcons } from '@expo/vector-icons';
import { AlgorithmInfo } from '../algorithms/AlgorithmRegistry';

interface AlgorithmSidebarProps {
  algorithms: AlgorithmInfo[];
  selectedAlgorithm: string;
  onSelectAlgorithm: (id: string) => void;
}

export default function AlgorithmSidebar({
  algorithms,
  selectedAlgorithm,
  onSelectAlgorithm,
}: AlgorithmSidebarProps) {
  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <MaterialIcons name="lock" size={20} color="#a78bfa" />
        <Text style={styles.headerText}>Algorytmy</Text>
      </View>
      <ScrollView style={styles.list}>
        {algorithms.map((algo) => (
          <TouchableOpacity
            key={algo.id}
            style={[
              styles.item,
              selectedAlgorithm === algo.id && styles.itemSelected,
            ]}
            onPress={() => onSelectAlgorithm(algo.id)}
          >
            <Text
              style={[
                styles.itemName,
                selectedAlgorithm === algo.id && styles.itemNameSelected,
              ]}
            >
              {algo.name}
            </Text>
            <Text style={styles.itemCategory}>{algo.category}</Text>
          </TouchableOpacity>
        ))}
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    backgroundColor: 'rgba(0, 0, 0, 0.3)',
    borderRadius: 12,
    padding: 16,
    marginBottom: 16,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 16,
    gap: 8,
  },
  headerText: {
    fontSize: 18,
    fontWeight: '600',
    color: '#fff',
  },
  list: {
    gap: 8,
  },
  item: {
    backgroundColor: 'rgba(30, 41, 59, 0.5)',
    padding: 12,
    borderRadius: 8,
    marginBottom: 8,
  },
  itemSelected: {
    backgroundColor: '#9333ea',
  },
  itemName: {
    color: '#fff',
    fontWeight: '500',
    fontSize: 14,
  },
  itemNameSelected: {
    color: '#fff',
  },
  itemCategory: {
    color: '#cbd5e1',
    fontSize: 12,
    marginTop: 4,
  },
});
