from core.mutator import Mutator
import random
from config.config import FUZZER_CONFIG


def _ensure_bytes(data):
    if data is None:
        return b''
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    if isinstance(data, str):
        return data.encode('utf-8', errors='ignore')
    try:
        return bytes(data)
    except Exception:
        return b''

class PlaintextMutator:
    def __init__(self):
        self.config = FUZZER_CONFIG.get('plaintext_mutator', {})
        self.mutator = Mutator()
        self.strategy_weights = self.config.get('strategy_weights', {
            'line_mutation': 0.6,
            'global_mutation': 0.2,
            'structure_mutation': 0.2
        })
    
    def _choose_strategy(self) -> str:
        rand = random.random()
        cumulative = 0
        for strategy, weight in self.strategy_weights.items():
            cumulative += weight
            if rand <= cumulative:
                return strategy
        return 'line_mutation'
    
    def _mutate_single_line(self, line: bytes, count: int) -> list:
        return self.mutator.generate_mutations(line, count=count)
    
    def _mutate_global_structure(self, lines: list, count: int) -> list:
        results = []
        
        for _ in range(count):
            mutated_lines = lines.copy()
            
            strategy = random.choice([
                self._shuffle_lines,
                self._repeat_lines,
                self._delete_lines,
                self._insert_empty_lines
            ])
            
            mutated_lines = strategy(mutated_lines)
            if mutated_lines and mutated_lines != lines:
                results.append(b'\n'.join(mutated_lines))
        
        return results[:count]
    
    def _shuffle_lines(self, lines: list) -> list:
        if len(lines) <= 1:
            return lines
        shuffled = lines.copy()
        random.shuffle(shuffled)
        return shuffled
    
    def _repeat_lines(self, lines: list) -> list:
        if not lines:
            return lines
        
        mutated = lines.copy()
        line_to_repeat = random.choice(mutated)
        repeat_count = random.randint(2, 5)
        insert_pos = random.randint(0, len(mutated))
        
        mutated[insert_pos:insert_pos] = [line_to_repeat] * repeat_count
        return mutated
    
    def _delete_lines(self, lines: list) -> list:
        if len(lines) <= 1:
            return lines
        
        mutated = lines.copy()
        delete_count = random.randint(1, min(3, len(mutated) - 1))
        
        for _ in range(delete_count):
            if len(mutated) > 1:
                del_idx = random.randint(0, len(mutated) - 1)
                del mutated[del_idx]
        
        return mutated
    
    def _insert_empty_lines(self, lines: list) -> list:
        if not lines:
            return [b'']
        
        mutated = lines.copy()
        insert_count = random.randint(1, 3)
        insert_pos = random.randint(0, len(mutated))
        
        mutated[insert_pos:insert_pos] = [b''] * insert_count
        return mutated
    
    def generate_mutations(self, data: bytes, count: int = 1000) -> list:
        lines = data.splitlines()
        
        if len(lines) <= 1:
            return self.mutator.generate_mutations(data, count=count)
        
        results = set()
        original_text = b'\n'.join(lines)
        
        line_mutation_count = int(count * 0.6)
        global_mutation_count = int(count * 0.3)
        structure_mutation_count = count - line_mutation_count - global_mutation_count
        
        if line_mutation_count > 0:
            line_results = []
            for line in lines:
                if line:
                    line_mutations = self._mutate_single_line(line, line_mutation_count // len(lines))
                    line_results.extend(line_mutations)
            
            for _ in range(line_mutation_count):
                try:
                    mutated_lines = []
                    for line in lines:
                        if line and line_results:
                            if random.choice([True, False]) and line_results:
                                mutated_lines.append(random.choice(line_results))
                            else:
                                mutated_lines.append(line)
                        else:
                            mutated_lines.append(line)
                    
                    result = b'\n'.join(mutated_lines)
                    if result != original_text:
                        results.add(result)
                except Exception:
                    continue
        
        if global_mutation_count > 0:
            global_mutations = self.mutator.generate_mutations(original_text, global_mutation_count)
            results.update(global_mutations)
        
        if structure_mutation_count > 0:
            structure_mutations = self._mutate_global_structure(lines, structure_mutation_count)
            results.update(structure_mutations)
        
        while len(results) < count:
            strategy = self._choose_strategy()
            if strategy == 'line_mutation':
                line_idx = random.randint(0, len(lines) - 1)
                if lines[line_idx]:
                    line_mutations = self._mutate_single_line(lines[line_idx], 1)
                    if line_mutations:
                        mutated_lines = lines.copy()
                        mutated_lines[line_idx] = line_mutations[0]
                        results.add(b'\n'.join(mutated_lines))
            elif strategy == 'global_mutation':
                global_mutations = self.mutator.generate_mutations(original_text, 1)
                if global_mutations:
                    results.add(global_mutations[0])
            else:
                structure_mutations = self._mutate_global_structure(lines, 1)
                if structure_mutations:
                    results.add(structure_mutations[0])
            
            if len(results) >= min(count, 10000):
                break
        
        return list(results)[:count]


def specific_mutate(monitor_data, original_data=None):
    plaintext_mutator = PlaintextMutator()
    monitor_bytes = _ensure_bytes(monitor_data)
    fallback_bytes = _ensure_bytes(original_data) if original_data is not None else b''

    if monitor_bytes:
        res = plaintext_mutator.generate_mutations(monitor_bytes, count=5000)
        if res:
            return res

    if fallback_bytes:
        return plaintext_mutator.generate_mutations(fallback_bytes, count=5000)

    return []

def plaintext_set(data, monitor_data=None):
    plaintext_mutator = PlaintextMutator()
    if monitor_data:
        mutated_data_list = specific_mutate(monitor_data, data)
        return mutated_data_list
    res = plaintext_mutator.generate_mutations(data, count=5000)
    return res