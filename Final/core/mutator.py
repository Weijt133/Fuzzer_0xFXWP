import random
import struct
from config.config import FUZZER_CONFIG

class Mutator:
    def __init__(self):
        self.config = FUZZER_CONFIG['mutator']
        self.interesting_ints = self.config['interesting_ints']
        self.interesting_strings = self.config['interesting_strings']
        self.strategy_weights = self.config['strategy_weights']

    def generate_mutations(self, data, count: int = 1000):
        mutations = []
        
        for _ in range(count):
            strategy = self._choose_strategy()
            mutated = self._apply_strategy(strategy, data)
            
            if mutated and mutated != data:
                mutations.append(mutated)
        
        return mutations[:count]

    def _choose_strategy(self) -> str:
        rand = random.random()
        cumulative = 0
        
        for strategy, weight in self.strategy_weights.items():
            cumulative += weight
            if rand <= cumulative:
                return strategy
        
        return 'bit_flip'

    def _apply_strategy(self, strategy: str, data: bytes) -> bytes:
        strategy_map = {
            'bit_flip': self.bit_flip_mutation,
            'byte_flip': self.byte_flip_mutation,
            'arithmetic': self.arithmetic_mutation,
            'interesting_int': self.interesting_int_mutation,
            'interesting_string': self.interesting_string_mutation,
            'repeat_or_truncate': self.repeat_or_truncate_mutation,
            'splice': self.splice_mutation,
            'dictionary': self.dictionary_mutation,
            'extreme_values': self.extreme_values_mutation,
        }
        
        return strategy_map.get(strategy, lambda x: x)(data)

    def _identify_data_type(self, data: bytes) -> str:
        if not data:
            return 'empty'
            
        try:
            text = data.decode('utf-8', errors='ignore').strip().lower()
            if text in ('true', 'false', 'yes', 'no', 'on', 'off'):
                return 'boolean'
            if text.isdigit() or (text.startswith('-') and text[1:].isdigit()):
                return 'integer'
            try:
                float(text)
                return 'float'
            except ValueError:
                pass
            if text.startswith(('{', '[', '<')) or ':' in text or '=' in text:
                return 'structured'
            return 'text'
            
        except:
            return 'binary'

    def bit_flip_mutation(self, data: bytes) -> bytes:
        if not data:
            return data
            
        data_array = bytearray(data)
        flip_count = max(1, int(len(data) * 0.2))
        
        for _ in range(flip_count):
            idx = random.randint(0, len(data_array) - 1)
            data_array[idx] ^= 1 << random.randint(0, 7)
        
        return bytes(data_array)

    def byte_flip_mutation(self, data: bytes) -> bytes:
        if not data:
            return data
            
        data_array = bytearray(data)
        flip_count = random.randint(1, min(10, len(data)))
        
        for _ in range(flip_count):
            idx = random.randint(0, len(data_array) - 1)
            data_array[idx] = random.randint(0, 255)
        
        return bytes(data_array)

    def arithmetic_mutation(self, data: bytes) -> bytes:
        data_type = self._identify_data_type(data)
        
        if data_type == 'integer':
            return self._mutate_integer(data)
        elif data_type == 'float':
            return self._mutate_float(data)
        elif data_type == 'boolean':
            return self._mutate_boolean(data)
        else:
            return self._binary_arithmetic_mutation(data)

    def _mutate_integer(self, data: bytes) -> bytes:
        try:
            num = int(data.decode('utf-8'))
            operations = [
                lambda x: x + 1, lambda x: x - 1, lambda x: x * 2,
                lambda x: x // 2, lambda x: -x, lambda x: x + random.randint(1, 100),
                lambda x: x - random.randint(1, 100), lambda x: x * 10,
                lambda x: 0, lambda x: 1, lambda x: -1,
                lambda x: random.choice(self.interesting_ints)
            ]
            result = random.choice(operations)(num)
            return str(result).encode('utf-8')
        except:
            return data

    def _mutate_float(self, data: bytes) -> bytes:
        try:
            num = float(data.decode('utf-8'))
            operations = [
                lambda x: x + 1.0, lambda x: x - 1.0, lambda x: x * 2.0,
                lambda x: x / 2.0, lambda x: -x, lambda x: x + random.random(),
                lambda x: x * 10.0, lambda x: 0.0, lambda x: 1.0,
                lambda x: float('inf'), lambda x: float('-inf'), lambda x: float('nan')
            ]
            result = random.choice(operations)(num)
            return str(result).encode('utf-8')
        except:
            return data

    def _mutate_boolean(self, data: bytes) -> bytes:
        text = data.decode('utf-8', errors='ignore').strip().lower()
        
        if text in ('true', 'yes', 'on', '1'):
            alternatives = ['false', 'no', 'off', '0']
        else:
            alternatives = ['true', 'yes', 'on', '1']
        
        return random.choice(alternatives).encode('utf-8')

    def _binary_arithmetic_mutation(self, data: bytes) -> bytes:
        if len(data) < 4:
            return data
            
        data_array = bytearray(data)
        for _ in range(random.randint(1, 2)):
            if len(data) >= 8 and random.choice([True, False]):
                self._modify_binary_integer(data_array, 8)
            elif len(data) >= 4:
                self._modify_binary_integer(data_array, 4)
        
        return bytes(data_array)

    def _modify_binary_integer(self, data: bytearray, size: int):
        try:
            start_idx = random.randint(0, len(data) - size)
            
            if size == 8:
                original = struct.unpack('<Q', data[start_idx:start_idx+8])[0]
                operations = [
                    lambda x: x + 1, lambda x: x - 1, lambda x: x * 2,
                    lambda x: x // 2, lambda x: x ^ 0xffffffffffffffff
                ]
                new_val = random.choice(operations)(original) & 0xffffffffffffffff
                new_bytes = struct.pack('<Q', new_val)
            else:  
                original = struct.unpack('<I', data[start_idx:start_idx+4])[0]
                operations = [
                    lambda x: x + 1, lambda x: x - 1, lambda x: x * 2,
                    lambda x: x // 2, lambda x: x ^ 0xffffffff
                ]
                new_val = random.choice(operations)(original) & 0xffffffff
                new_bytes = struct.pack('<I', new_val)
            
            data[start_idx:start_idx+size] = new_bytes
        except (struct.error, ValueError):
            pass

    def interesting_int_mutation(self, data: bytes) -> bytes:
        if len(data) < 4:
            return data
            
        data_array = bytearray(data)
        interesting_val = random.choice(self.interesting_ints)
        
        for _ in range(random.randint(1, 2)):
            if len(data) >= 8 and random.choice([True, False]):
                start_idx = random.randint(0, len(data) - 8)
                try:
                    new_bytes = struct.pack('<Q', interesting_val & 0xffffffffffffffff)
                    data_array[start_idx:start_idx+8] = new_bytes
                except:
                    pass
            elif len(data) >= 4:
                start_idx = random.randint(0, len(data) - 4)
                try:
                    new_bytes = struct.pack('<I', interesting_val & 0xffffffff)
                    data_array[start_idx:start_idx+4] = new_bytes
                except:
                    pass
        
        return bytes(data_array)

    def interesting_string_mutation(self, data: bytes) -> bytes:
        if not data:
            return random.choice(self.interesting_strings)
            
        interesting_str = random.choice(self.interesting_strings)
        
        if random.choice([True, False]):
            pos = random.randint(0, len(data))
            return data[:pos] + interesting_str + data[pos:]
        else:
            if len(interesting_str) <= len(data):
                start = random.randint(0, len(data) - len(interesting_str))
                return data[:start] + interesting_str + data[start+len(interesting_str):]
        
        return data

    def repeat_or_truncate_mutation(self, data: bytes) -> bytes:
        if not data:
            return data
            
        if random.choice([True, False]) and len(data) > 1:
            start = random.randint(0, len(data) - 1)
            end = random.randint(start + 1, len(data))
            substring = data[start:end]
            repeat_count = random.randint(2, 5)
            
            pos = random.randint(0, len(data))
            return data[:pos] + (substring * repeat_count) + data[pos:]
        else:
            if len(data) > 1:
                return data[:random.randint(1, len(data) - 1)]
        
        return data

    def splice_mutation(self, data: bytes) -> bytes:
        if len(data) < 2:
            return data
            
        parts = [data[:len(data)//2], data[len(data)//2:]]
        random.shuffle(parts)
        return b''.join(parts)

    def dictionary_mutation(self, data: bytes) -> bytes:
        if not data:
            return random.choice(self.interesting_strings)
            
        patterns = [
            (b'admin', b'root'), (b'user', b'admin'), (b'password', b'pass'),
            (b'true', b'false'), (b'false', b'true'), (b'null', b'undefined'),
            (b'http://', b'https://'), (b'www.', b'api.'), (b'.com', b'.org')
        ]
        
        for old, new in patterns:
            if old in data:
                return data.replace(old, new)
        
        return data

    def extreme_values_mutation(self, data: bytes) -> bytes:
        if not data:
            return b'A' * 100
            
        extremes = [
            data * 1000,
            b'\x00' * 1000,
            b'\xff' * 1000,
            b'A' * 10000,
            b'',
            data.replace(b' ', b'\x00'),
            data[:1] if len(data) > 1 else data,
        ]
        
        return random.choice(extremes)


if __name__ == "__main__":
    mutator = Mutator()
    sample_data = b"sample input data"
    mutated_data = mutator.generate_mutations(sample_data, count=5)
    print(f"Generated {len(mutated_data)} mutations")