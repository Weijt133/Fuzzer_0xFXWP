import lief
import random
import copy
import string
import os
import tempfile
import struct
from typing import Optional, List, Set

class ByteLevelMutator:
    def __init__(self, seed: Optional[int] = None):
        self.random = random.Random(seed)

    def _to_ba(self, data: bytes) -> bytearray:
        if data is None:
            return bytearray()
        if isinstance(data, bytearray):
            return data[:]
        return bytearray(data)

    def flip_bit(self, data: bytes) -> bytes:
        ba = self._to_ba(data)
        if not ba:
            return bytes(ba)
        pos = self.random.randint(0, len(ba) - 1)
        bit = 1 << self.random.randint(0, 7)
        ba[pos] ^= bit
        return bytes(ba)

    def insert_byte(self, data: bytes) -> bytes:
        ba = self._to_ba(data)
        pos = self.random.randint(0, len(ba))
        byte = self.random.randint(0, 255)
        new_ba = ba[:pos] + bytearray([byte]) + ba[pos:]
        return bytes(new_ba)

    def delete_byte(self, data: bytes) -> bytes:
        ba = self._to_ba(data)
        if not ba:
            return bytes(ba)
        if len(ba) == 1:
            return b""
        pos = self.random.randint(0, len(ba) - 1)
        new_ba = ba[:pos] + ba[pos+1:]
        return bytes(new_ba)

    def generate_mutations(self, data: bytes, count: int = 100) -> List[bytes]:
        if data is None:
            data = b""
        if not isinstance(data, (bytes, bytearray)):
            try:
                data = bytes(data)
            except Exception:
                data = b""

        mutations: List[bytes] = []
        for _ in range(count):
            mutation_type = self.random.choice(['flip', 'insert', 'delete'])
            try:
                if mutation_type == 'flip':
                    mutated = self.flip_bit(data)
                elif mutation_type == 'insert':
                    mutated = self.insert_byte(data)
                else: # 'delete'
                    if len(data) > 1:
                        mutated = self.delete_byte(data)
                    else:
                        mutated = self.insert_byte(data)
                if mutated is not None:
                    mutations.append(mutated)
            except Exception:
                continue

        unique: List[bytes] = []
        seen = set()
        for m in mutations:
            h = hash(m)
            if h not in seen:
                seen.add(h)
                unique.append(m)
        return unique


class ELFMutator:
    ELF_FUZZ_VALUES = {
        "INTS": [
            0, 1, -1, 2**31-1, 2**32, 2**63-1, 2**64-1,
            0xFFFF, 0xFFFFFFFF, 0x80000000, 0xFFFFFFFFFFFFFFFF,
            2**64 - 100, 2**64 - 56, 2**64 - 32, 2**64 - 1,
        ],
        "STRINGS": ["/bin/sh", ".text", ".data", ".bss", "A"*1024, "' OR 1=1 --", "%s%n%p"],
        "E_TYPE": [lief.ELF.Header.FILE_TYPE.CORE, lief.ELF.Header.FILE_TYPE.DYN, lief.ELF.Header.FILE_TYPE.REL, 99],
        "E_MACHINE": [lief.ELF.ARCH.AARCH64, lief.ELF.ARCH.ARM, lief.ELF.ARCH.I386, lief.ELF.ARCH.X86_64, 999],
        "SEGMENT_FLAGS": [0, 1, 2, 3, 4, 5, 6, 7],
    }

    def __init__(self):
        self.byte_mutator = ByteLevelMutator()
        self.strategy_weights = {
            '_mutate_direct_bytes': 0.25, 
            '_mutate_integer_overflow': 0.20, 
            '_mutate_header': 0.15,
            '_mutate_sections': 0.10,
            '_mutate_program_headers': 0.10,
            '_mutate_dynamic': 0.05,
            '_mutate_symbols_relocations': 0.05,
            '_mutate_evasion': 0.05,
            '_fallback_byte_mutation': 0.05,
        }

    def _choose_strategy(self) -> str:
        strategies = list(self.strategy_weights.keys())
        weights = list(self.strategy_weights.values())
        return random.choices(strategies, weights=weights, k=1)[0]

    def _parse_elf(self, data: bytes) -> Optional[lief.ELF.Binary]:
        if not data:
            return None
        try:
            bytes_data = bytes(data)
        except Exception:
            return None

        try:
            def on_error(msg): pass
            parsed = lief.parse(bytes_data, on_error=on_error)
            if isinstance(parsed, lief.ELF.Binary):
                return parsed
        except Exception:
            pass
        return None

    def _render_elf(self, binary: lief.ELF.Binary) -> Optional[bytes]:
        if not isinstance(binary, lief.ELF.Binary):
            return None
        try:
            builder = lief.ELF.Builder(binary)
            builder.build()
            built = builder.get_build()
            if built:
                return bytes(built)
        except Exception:
            pass
        return None

    def _mutate_direct_bytes(self, data: bytes) -> Optional[bytes]:
        if len(data) < 64: return None

        ba = bytearray(data)
        is_64bit = (ba[4] == 2)
        is_le = (ba[5] == 1)
        endian_fmt = '<' if is_le else '>'

        if not is_64bit: return None

        try:
            choice = random.randint(1, 4)
            if choice == 1:
                shnum_offset, shentsize_offset = 60, 58
                struct.pack_into(endian_fmt + 'H', ba, shnum_offset, 0xFFFF)
                struct.pack_into(endian_fmt + 'H', ba, shentsize_offset, 0xFFFF)
            elif choice == 2:
                shoff_offset = 40
                malicious_offset = 0xFFFFFFFFFFFFFFE0
                struct.pack_into(endian_fmt + 'Q', ba, shoff_offset, malicious_offset)
                struct.pack_into(endian_fmt + 'H', ba, 60, 1)
                struct.pack_into(endian_fmt + 'H', ba, 58, 32)
            elif choice == 3:
                e_shoff = struct.unpack_from(endian_fmt + 'Q', ba, 40)[0]
                e_shnum = struct.unpack_from(endian_fmt + 'H', ba, 60)[0]
                e_shentsize = struct.unpack_from(endian_fmt + 'H', ba, 58)[0]
                if e_shnum == 0 or e_shentsize == 0: return None
                if e_shoff + (e_shnum * e_shentsize) > len(ba): return None
                random_section_idx = random.randint(0, e_shnum - 1)
                section_header_base = e_shoff + (random_section_idx * e_shentsize)
                if section_header_base + 40 > len(ba): return None
                offset_field_pos = section_header_base + 24
                size_field_pos = section_header_base + 32
                struct.pack_into(endian_fmt + 'Q', ba, offset_field_pos, len(data) - 20)
                struct.pack_into(endian_fmt + 'Q', ba, size_field_pos, 0xFFFFFFFFFFFFFFFF)
            elif choice == 4:
                shnum_offset, shstrndx_offset = 60, 62
                if len(ba) >= shstrndx_offset + 2:
                    num_sections = struct.unpack_from(endian_fmt + 'H', ba, shnum_offset)[0]
                    if num_sections > 0:
                        struct.pack_into(endian_fmt + 'H', ba, shstrndx_offset, num_sections)
            return bytes(ba)
        except (struct.error, IndexError):
            return None

    def _mutate_header(self, b: lief.ELF.Binary, orig_bytes: bytes) -> Optional[lief.ELF.Binary]:
        try:
            hdr = b.header
            choice = random.randint(1, 8)
            if choice == 1:
                hdr.file_type = random.choice(self.ELF_FUZZ_VALUES["E_TYPE"])
                hdr.machine_type = random.choice(self.ELF_FUZZ_VALUES["E_MACHINE"])
            elif choice == 2:
                hdr.entrypoint = random.choice(self.ELF_FUZZ_VALUES["INTS"])
            elif choice == 3:
                hdr.numberof_program_headers = random.randint(0, 0xFFFF)
                hdr.numberof_section_headers = random.randint(0, 0xFFFF)
            elif choice == 4:
                hdr.identity_class = (lief.ELF.ELF_CLASS.CLASS64 if hdr.identity_class == lief.ELF.ELF_CLASS.CLASS32 else lief.ELF.ELF_CLASS.CLASS32)
            elif choice == 5:
                hdr.identity_data = random.choice([lief.ELF.ELF_DATA.LSB, lief.ELF.ELF_DATA.MSB, lief.ELF.ELF_DATA.NONE])
            elif choice == 6:
                if len(orig_bytes) > 200 and b.sections:
                    target_section = random.choice(b.sections)
                    target_section.offset = len(orig_bytes) - random.randint(50, 100)
                    target_section.size = 0xFFFFFFFFFFFFFFFF - random.randint(0, 100)
            elif choice == 7:
                hdr.numberof_program_headers = random.randint(0x1000, 0xFFFF)
                hdr.numberof_section_headers = random.randint(0x1000, 0xFFFF)
            elif choice == 8:
                if hdr.numberof_section_headers > 0:
                    hdr.section_name_table_idx = random.randint(hdr.numberof_section_headers, hdr.numberof_section_headers + 100)
            return b
        except Exception:
            return None

    def _mutate_program_headers(self, b: lief.ELF.Binary, **kwargs) -> Optional[lief.ELF.Binary]:
        try:
            if not b.segments: return None
            target_segment = random.choice(b.segments)
            choice = random.randint(1, 5)
            if choice == 1:
                target_segment.virtual_size = random.choice(self.ELF_FUZZ_VALUES["INTS"])
            elif choice == 2:
                target_segment.flags = random.choice(self.ELF_FUZZ_VALUES["SEGMENT_FLAGS"])
            elif choice == 3 and len(b.segments) > 1:
                s1, s2 = random.sample(b.segments, 2)
                s2.virtual_address = s1.virtual_address + (s1.virtual_size // 2)
            elif choice == 4:
                target_segment.type = random.choice([lief.ELF.SEGMENT_TYPES.LOAD, lief.ELF.SEGMENT_TYPES.INTERP, 0xFF])
            elif choice == 5 and len(b.segments) > 1:
                s1, s2 = random.sample(b.segments, 2)
                if s1.physical_size > 1:
                    s2.offset = s1.offset + random.randint(1, s1.physical_size // 2)
            return b
        except Exception:
            return None

    def _mutate_sections(self, b: lief.ELF.Binary, orig_bytes: bytes) -> Optional[lief.ELF.Binary]:
        try:
            if not b.sections: return None
            target_section = random.choice(b.sections)
            choice = random.randint(1, 5)
            if choice == 1:
                target_section.size = random.choice(self.ELF_FUZZ_VALUES["INTS"])
            elif choice == 2:
                target_section.name = random.choice(self.ELF_FUZZ_VALUES["STRINGS"])
            elif choice == 3:
                target_section.type = random.randint(0, 0xFF)
            elif choice == 4:
                for i in range(random.randint(20, 50)):
                    new_section = lief.ELF.Section(f".fuzz_{i}", lief.ELF.SECTION_TYPES.PROGBITS)
                    new_section.content = [random.randint(0, 255) for _ in range(10)]
                    b.add(new_section, loaded=False)
            elif choice == 5:
                target_section.size = 0xFFFFFFFFFFFFFFFF
                if len(orig_bytes) > 0:
                    target_section.offset = len(orig_bytes) + random.randint(100, 1000)
            return b
        except Exception:
            return None

    def _mutate_dynamic(self, b: lief.ELF.Binary, **kwargs) -> Optional[lief.ELF.Binary]:
        try:
            if not b.has_dynamic_entries: return None
            choice = random.randint(1, 4)
            if choice == 1 and b.has_dynamic(lief.ELF.DYNAMIC_TAGS.NEEDED):
                for entry in b.get_dynamic_entries(lief.ELF.DYNAMIC_TAGS.NEEDED):
                    entry.name = "a" * random.randint(100, 500)
            elif choice == 2:
                tag = random.choice([lief.ELF.DYNAMIC_TAGS.DEBUG, lief.ELF.DYNAMIC_TAGS.TEXTREL])
                if b.has_dynamic(tag): b.remove_dynamic(tag)
                else: b.add(lief.ELF.DynamicEntry(tag, 1234))
            elif choice == 3 and b.has_dynamic(lief.ELF.DYNAMIC_TAGS.RUNPATH):
                runpath = b.get_dynamic_entry(lief.ELF.DYNAMIC_TAGS.RUNPATH)
                runpath.value = random.choice(self.ELF_FUZZ_VALUES["STRINGS"])
            elif choice == 4 and b.has_dynamic(lief.ELF.DYNAMIC_TAGS.STRTAB):
                b.remove_dynamic(lief.ELF.DYNAMIC_TAGS.STRTAB)
            return b
        except Exception:
            return None

    def _mutate_symbols_relocations(self, b: lief.ELF.Binary, **kwargs) -> Optional[lief.ELF.Binary]:
        try:
            if b.symbols:
                target_symbol = random.choice(b.symbols)
                target_symbol.name = random.choice(self.ELF_FUZZ_VALUES["STRINGS"])
                target_symbol.value = random.choice(self.ELF_FUZZ_VALUES["INTS"])
            if b.relocations:
                target_relocation = random.choice(b.relocations)
                target_relocation.address = random.choice(self.ELF_FUZZ_VALUES["INTS"])
            return b
        except Exception:
            return None

    def _mutate_evasion(self, b: lief.ELF.Binary, **kwargs) -> Optional[lief.ELF.Binary]:
        try:
            suspicious_string = b"EVIL_PAYLOAD_DETECT_ME"
            if random.random() < 0.5:
                note = lief.ELF.Note("FUZZ", lief.ELF.NOTE_TYPES.GENERIC, list(suspicious_string))
                b.add(note)
            else:
                section = lief.ELF.Section(".comment", lief.ELF.SECTION_TYPES.PROGBITS)
                section.content = list(suspicious_string)
                b.add(section)
            return b
        except Exception:
            return None

    def _mutate_integer_overflow(self, b: lief.ELF.Binary, orig_bytes: bytes) -> Optional[lief.ELF.Binary]:
        try:
            if len(orig_bytes) < 128: return None
            hdr = b.header
            choice = random.randint(1, 2)
            if choice == 1:
                hdr.section_headers_offset = len(orig_bytes) - random.randint(32, 64)
                hdr.numberof_section_headers = random.choice([0xFFFF, 0xFFFE])
                hdr.section_header_size = random.choice([0xFFFF, 0xFFFE])
            elif choice == 2:
                load_segments = [s for s in b.segments if s.type == lief.ELF.SEGMENT_TYPES.LOAD]
                if not load_segments: return None
                target_segment = random.choice(load_segments)
                target_segment.offset = len(orig_bytes) - random.randint(32, 64)
                target_segment.physical_size = 0xFFFFFFFFFFFFFFFF
            return b
        except Exception:
            return None

    def _fallback_byte_mutation(self, data: bytes, **kwargs) -> Optional[bytes]:
        return self.byte_mutator.generate_mutations(data, count=1)[0]

    def generate_mutations(self, data: bytes, count: int = 3000) -> List[bytes]:
        if not data:
            return []

        orig_bytes = bytes(data)
        mutations: Set[bytes] = {orig_bytes}
        
        binary = self._parse_elf(orig_bytes)

        if binary is None:
            all_muts = []
            for _ in range(count):
                base = random.choice(list(mutations))
                all_muts.extend(self.byte_mutator.generate_mutations(base, count=1))
            return list(set(all_muts))

        strategies = {
            '_mutate_direct_bytes': self._mutate_direct_bytes,
            '_mutate_header': self._mutate_header,
            '_mutate_program_headers': self._mutate_program_headers,
            '_mutate_sections': self._mutate_sections,
            '_mutate_dynamic': self._mutate_dynamic,
            '_mutate_symbols_relocations': self._mutate_symbols_relocations,
            '_mutate_evasion': self._mutate_evasion,
            '_mutate_integer_overflow': self._mutate_integer_overflow,
            '_fallback_byte_mutation': self._fallback_byte_mutation,
        }

        attempts = 0
        max_attempts = count * 5

        while len(mutations) < count and attempts < max_attempts:
            attempts += 1
            strategy_name = self._choose_strategy()
            strategy_func = strategies.get(strategy_name)
            if not strategy_func: continue

            try:
                if strategy_name in ['_mutate_direct_bytes', '_fallback_byte_mutation']:
                    base_sample = random.choice(list(mutations))
                    mutated_data = strategy_func(data=base_sample, orig_bytes=orig_bytes)
                    if mutated_data:
                        mutations.add(mutated_data)
                else:
                    binary_copy = copy.deepcopy(binary)
                    mutated_binary = strategy_func(b=binary_copy, orig_bytes=orig_bytes)
                    if mutated_binary:
                        rendered_data = self._render_elf(mutated_binary)
                        if rendered_data:
                            mutations.add(rendered_data)
            except Exception:
                continue
        
        return list(mutations)

def _ensure_bytes(data):
    if data is None: return b''
    if isinstance(data, bytes): return data
    if isinstance(data, bytearray): return bytes(data)
    try:
        return bytes(data)
    except Exception:
        return b''

def specific_mutate(monitor_data, original_data=None):
    elf_mutator = ELFMutator()
    monitor_bytes = _ensure_bytes(monitor_data)
    fallback_bytes = _ensure_bytes(original_data) if original_data is not None else b''

    seed_data = monitor_bytes if monitor_bytes else fallback_bytes
    
    if seed_data:
        return elf_mutator.generate_mutations(seed_data, count=3000)
    
    return []

def elf_set(data, monitor_data=None):
    if monitor_data:
        return specific_mutate(monitor_data, data)
    
    elf_mutator = ELFMutator()
    seed_bytes = _ensure_bytes(data)
    return elf_mutator.generate_mutations(seed_bytes, count=3000)