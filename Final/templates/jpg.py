from core.mutator import Mutator
from config.config import FUZZER_CONFIG
import random
import struct


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

class JPGMutator:
    def __init__(self):
        self.config = FUZZER_CONFIG.get('jpg_template')
        
        self.mutator = Mutator()
        self.strategy_weights = self.config['strategy_weights']
        self.interesting_ints = self.config.get('interesting_integers', [0, 65535])
        self.max_expansion = self.config.get('max_segment_expansion', 4096)

    def _choose_strategy(self) -> str:
        rand = random.random()
        cumulative = 0
        for strategy, weight in self.strategy_weights.items():
            cumulative += weight
            if rand <= cumulative:
                return strategy
        return 'bit_flip'

    def _parse_structure(self, data):
        structure = {
            "segments": [],       
            "integer_fields": [], 
            "entropy": None       
        }

        if len(data) < 4 or data[0:2] != b'\xff\xd8':
            return None

        pos = 2
        length = len(data)
        
        while pos < length:
            if data[pos] != 0xff:
                pos = data.find(b'\xff', pos)
                if pos == -1: break
                continue
            
            while pos < length and data[pos] == 0xff:
                pos += 1
            
            if pos >= length: break
            marker = data[pos]
            pos += 1 

            if marker in [0xd8, 0xd9, 0x01] or (0xd0 <= marker <= 0xd7):
                continue
            
            if pos + 2 > length: break
            try:
                seg_len = struct.unpack('>H', data[pos:pos+2])[0]
            except struct.error:
                break
            
            seg_start = pos - 1
            content_start = pos + 2
            seg_end = pos + seg_len
            
            segment_info = {
                'marker': marker,
                'start': seg_start,
                'end': seg_end,
                'content_start': content_start,
                'length': seg_len
            }
            structure["segments"].append(segment_info)

            if marker in [0xc0, 0xc2]: 
                structure["integer_fields"].append((content_start + 1, 'u16be')) 
                structure["integer_fields"].append((content_start + 3, 'u16be'))
            elif marker == 0xdd:
                structure["integer_fields"].append((content_start, 'u16be'))

            if marker == 0xda:
                eoi_pos = data.rfind(b'\xff\xd9')
                if eoi_pos == -1: eoi_pos = length
                if eoi_pos > seg_end:
                    structure["entropy"] = (seg_end, eoi_pos)
                break 

            pos += seg_len

        return structure



    def mutate_structure_integers(self, data, structure):
        if not structure or not structure['segments']:
            return None

        if random.random() < 0.3:
            new_data = bytearray()
            
            new_data += b'\xFF\xD8'
            
            has_replaced_sof = False
            
            for seg in structure['segments']:
                marker = seg['marker']
                
                if marker in [0xc0, 0xc2]: 
                    payload = b'\xFF\xC0\x00\x0B\x08\xFF\xFF\xFF\xFF\x01\x01\x11\x00'
                    new_data += payload
                    has_replaced_sof = True
                    
                elif marker == 0xda: 
                    header = b'\xFF\xDA\x00\x08\x01\x01\x00\x00\x3F\x00'
                    new_data += header
                    
                    if structure['entropy']:
                        start, end = structure['entropy']
                        new_data += data[start:end]
                    else:
                        new_data += b'\x00' * 1024
                    
                    break
                    
                else:
                    new_data += data[seg['start']-1 : seg['end']]

            new_data += b'\xFF\xD9'
            
            if has_replaced_sof:
                return bytes(new_data)

        mutated = bytearray(data)
        if not structure['integer_fields']:
            return None

        targets = random.sample(structure['integer_fields'], min(len(structure['integer_fields']), 3))
        for offset, fmt in targets:
            val = random.choice(self.interesting_ints)
            if fmt == 'u16be':
                val = val & 0xFFFF
                mutated[offset] = (val >> 8) & 0xFF
                mutated[offset + 1] = val & 0xFF
        
        return bytes(mutated)

    def mutate_segment_size(self, data, structure):
        if not structure or not structure['segments']:
            return None
        
        candidates = [s for s in structure['segments'] if (0xe0 <= s['marker'] <= 0xef) or s['marker'] == 0xfe]
        
        if not candidates:
            if len(data) > 2:
                new_payload = b'X' * random.randint(1000, self.max_expansion)
                new_len = len(new_payload) + 2
                segment = b'\xff\xe0' + struct.pack('>H', new_len) + new_payload
                return data[:2] + segment + data[2:]
            return None
            
        target_seg = random.choice(candidates)
        new_size = random.randint(100, self.max_expansion)
        new_payload = b'A' * new_size
        
        if random.random() < 0.8:
            new_len_field = struct.pack('>H', new_size + 2)
        else:
            new_len_field = struct.pack('>H', random.randint(0, 65535))
            
        marker_byte = bytes([target_seg['marker']])
        prefix = data[:target_seg['start']-1]
        suffix = data[target_seg['end']:]
        
        new_segment = b'\xff' + marker_byte + new_len_field + new_payload
        return prefix + new_segment + suffix

    def mutate_entropy_data(self, data, structure):
        if not structure or not structure["entropy"]:
            return None
        start, end = structure["entropy"]
        if start >= end: return None
        entropy_chunk = data[start:end]
        mutations = self.mutator.generate_mutations(entropy_chunk, count=1)
        if mutations:
            return data[:start] + mutations[0] + data[end:]
        return None

    def shuffle_segments(self, data, structure):
        if not structure or not structure['segments']:
            return None
        segments = structure['segments']
        if len(segments) < 2: return None
        
        seg_blobs = []
        header = data[:segments[0]['start']-1] 
        for s in segments:
            seg_blobs.append(data[s['start']-1 : s['end']])
        footer = data[segments[-1]['end']:]
        
        action = random.choice(['delete', 'duplicate', 'swap'])
        if action == 'delete':
            seg_blobs.pop(random.randint(0, len(seg_blobs)-1))
        elif action == 'duplicate':
            idx = random.randint(0, len(seg_blobs)-1)
            seg_blobs.insert(idx, seg_blobs[idx])
        elif action == 'swap':
            i, j = random.sample(range(len(seg_blobs)), 2)
            seg_blobs[i], seg_blobs[j] = seg_blobs[j], seg_blobs[i]
            
        return header + b''.join(seg_blobs) + footer

    def bit_flip(self, data, structure=None):
        if len(data) < 4: return data
        result = bytearray(data)
        num_flips = max(1, int(len(data) * 0.005))
        for _ in range(num_flips):
            pos = random.randint(0, len(data) - 1)
            if result[pos] == 0xff: continue
            result[pos] ^= (1 << random.randint(0, 7))
        return bytes(result)

    def generate_mutations(self, data: bytes, count: int = 1000):
        results = set()
        results.add(data)
        
        structure = self._parse_structure(data)
        
        strategies = {
            'mutate_structure_integers': self.mutate_structure_integers,
            'mutate_segment_size': self.mutate_segment_size,
            'mutate_entropy_data': self.mutate_entropy_data,
            'shuffle_segments': self.shuffle_segments,
            'bit_flip': self.bit_flip
        }

        attempts = 0
        max_attempts = count * 3

        while len(results) < count and attempts < max_attempts:
            attempts += 1
            strategy_name = self._choose_strategy()
            strategy_func = strategies[strategy_name]

            try:
                res = strategy_func(data, structure)
                if res and res != data:
                    results.add(res)
            except Exception:
                continue
        
        result_list = list(results)
        while len(result_list) < count:
            result_list.append(self.bit_flip(data))

        return result_list[:count]


def specific_mutate(monitor_data, original_data=None):
    jpg_mutator = JPGMutator()
    monitor_bytes = _ensure_bytes(monitor_data)
    fallback_bytes = _ensure_bytes(original_data) if original_data is not None else b''

    if monitor_bytes and jpg_mutator._parse_structure(monitor_bytes):
        return jpg_mutator.generate_mutations(monitor_bytes, count=1000)

    if fallback_bytes:
        return jpg_mutator.generate_mutations(fallback_bytes, count=1000)

    if monitor_bytes:
        return jpg_mutator.generate_mutations(monitor_bytes, count=1000)

    return []


def jpg_set(data: bytes, monitor_data=None):
    jpg_mutator = JPGMutator()
    if monitor_data:
        return specific_mutate(monitor_data, data)
    return jpg_mutator.generate_mutations(data, count=1000)