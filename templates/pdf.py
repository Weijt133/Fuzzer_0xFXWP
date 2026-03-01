import os
import random
import re
from typing import Callable, List, Optional

from core.mutator import Mutator


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


def _looks_like_pdf(payload):
    if not payload:
        return False
    prefix = payload.lstrip()[:5]
    return prefix.startswith(b'%PDF-')


PDF_VERSIONS = [b"1.0", b"1.1", b"1.2", b"1.3", b"1.4", b"1.5", b"1.6", b"1.7", b"2.0"]
JS_PAYLOADS = [
    b"app.alert('FUZZ');",
    b"this.print({bUI:true,bSilent:false});",
    b"while(true){app.alert('loop');}",
    b"this.exportDataObject({cName:'fuzz',nLaunch:2});",
    b"var x = util.printf('%999999s', 'A');",
]
STREAM_NOISE = [
    b"A" * 4096,
    b"%PDF-FUZZ%" * 512,
    os.urandom(2048),
]
LENGTH_EXTREMES = [b"2147483648", b"3000000000", b"4294967295", b"9999999999", b"-1"]


class PDFMutator:
    def __init__(self):
        self.mutator = Mutator()
        self.object_decl_pattern = re.compile(br"(\d+)\s+(\d+)\s+obj")
        self.length_pattern = re.compile(br"/Length\s+(\d+)")
        self.length_value_pattern = re.compile(br"(/Length\s+)(-?\d+)")
        self.stream_pattern = re.compile(br"stream\r?\n(.*?)\r?\nendstream", re.S)
        self.trailer_pattern = re.compile(br"(trailer\s*<<[\s\S]*?>>)", re.I)
        self.catalog_pattern = re.compile(br"<<[\s\S]{0,4096}?/Type\s*/Catalog[\s\S]{0,4096}?>>")
        self.reference_pattern = re.compile(br"(\d+)\s+(\d+)\s+R")
        self.entry_pattern = re.compile(br"(\d{10}) (\d{5}) ([nf])")
        self.strategy_funcs: List[Callable[[bytes], Optional[bytes]]] = [
            self._force_huge_length,
            self._insert_decoy_length_early,
            self._misordered_stream_markers,
            self._mutate_header,
            self._tamper_object_numbers,
            self._mutate_references,
            self._stream_length_mismatch,
            self._stream_payload_flood,
            self._inject_javascript_action,
            self._corrupt_xref,
            self._truncate_or_pad,
            self._incremental_update,
        ]

    def _escape_literal(self, payload: bytes) -> bytes:
        return payload.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")

    def _next_object_id(self, data: bytes) -> int:
        ids = [int(match.group(1)) for match in self.object_decl_pattern.finditer(data)]
        if not ids:
            return random.randint(1, 1024)
        return max(ids) + random.randint(1, 6)

    def _mutate_header(self, data: bytes) -> Optional[bytes]:
        new_version = random.choice(PDF_VERSIONS)
        replacement = b"%PDF-" + new_version
        header_match = re.search(br"%PDF-\d\.\d", data[:1024])
        noise = b"\n%" + os.urandom(16) + b"\n"
        if header_match:
            prefix = data[:header_match.start()]
            suffix = data[header_match.end():]
            return prefix + replacement + noise + suffix
        return replacement + noise + data

    def _tamper_object_numbers(self, data: bytes) -> Optional[bytes]:
        matches = list(self.object_decl_pattern.finditer(data))
        if not matches:
            return None
        target_matches = random.sample(matches, min(len(matches), random.randint(1, 5)))
        mutated = bytearray(data)
        for match in sorted(target_matches, key=lambda m: m.start(), reverse=True):
            obj_id = int(match.group(1))
            gen_id = int(match.group(2))
            new_id = max(0, obj_id + random.randint(-25, 50))
            new_gen = max(0, min(9, gen_id + random.randint(-2, 3)))
            replacement = f"{new_id} {new_gen} obj".encode("ascii")
            start, end = match.span()
            mutated[start:end] = replacement
        return bytes(mutated)

    def _force_huge_length(self, data: bytes) -> Optional[bytes]:
        m = self.length_value_pattern.search(data)
        if not m:
            return None
        replacement = m.group(1) + random.choice(LENGTH_EXTREMES)
        start, end = m.span()
        return data[:start] + replacement + data[end:]

    def _insert_decoy_length_early(self, data: bytes) -> Optional[bytes]:

        header_match = re.search(br"%PDF-\d\.\d", data[:1024])
        decoy = b"\n/Length 9999999999\n"
        if header_match:
            insert_pos = header_match.end()
            if b"/Length" not in data[: min(len(data), insert_pos + 128)]:
                return data[:insert_pos] + decoy + data[insert_pos:]
            return None
        if not data.startswith(b"%PDF-"):
            return b"%PDF-1.4" + decoy + data
        return None

    def _misordered_stream_markers(self, data: bytes) -> Optional[bytes]:

        stream_idx = data.find(b"stream")
        if stream_idx == -1:
            return None
        first_end_idx = data.find(b"endstream")
        if first_end_idx != -1 and first_end_idx < stream_idx:
            return None 
        header_match = re.search(br"%PDF-\d\.\d", data[:1024])
        insert_pos = header_match.end() if header_match else 0
        return data[:insert_pos] + b"\nendstream\n" + data[insert_pos:]

    def _mutate_references(self, data: bytes) -> Optional[bytes]:
        matches = list(self.reference_pattern.finditer(data))
        if not matches:
            return None
        target_matches = random.sample(matches, min(len(matches), random.randint(1, 6)))
        mutated = bytearray(data)
        for match in sorted(target_matches, key=lambda m: m.start(), reverse=True):
            obj_id = int(match.group(1))
            gen_id = int(match.group(2))
            new_obj = max(0, obj_id + random.randint(-64, 128))
            new_gen = max(0, min(9, gen_id + random.randint(-2, 4)))
            replacement = f"{new_obj} {new_gen} R".encode("ascii")
            start, end = match.span()
            mutated[start:end] = replacement
        return bytes(mutated)

    def _stream_length_mismatch(self, data: bytes) -> Optional[bytes]:
        matches = list(self.length_pattern.finditer(data))
        if not matches:
            return None
        match = random.choice(matches)
        length_val = int(match.group(1))
        delta = random.choice([-4096, -1024, -1, 1, 1024, 8192, 65535])
        new_length = max(0, length_val + delta)
        replacement = str(new_length).encode("ascii")
        start, end = match.span(1)
        return data[:start] + replacement + data[end:]

    def _stream_payload_flood(self, data: bytes) -> Optional[bytes]:
        matches = list(self.stream_pattern.finditer(data))
        if not matches:
            return None
        match = random.choice(matches)
        stream_content = match.group(1)
        snippet = stream_content[: min(len(stream_content), 512)] or b"x"
        repetition = random.randint(2, 10)
        new_stream = snippet * repetition + random.choice(STREAM_NOISE)
        return data[: match.start(1)] + new_stream + data[match.end(1):]

    def _inject_javascript_action(self, data: bytes) -> Optional[bytes]:
        js_obj_id = self._next_object_id(data)
        js_payload = self._escape_literal(random.choice(JS_PAYLOADS))
        js_object = (
            b"\n"
            + str(js_obj_id).encode("ascii")
            + b" 0 obj\n<< /Type /Action /S /JavaScript /JS ("
            + js_payload
            + b") >>\nendobj\n"
        )

        mutated = data
        catalog_match = self.catalog_pattern.search(mutated)
        ref = str(js_obj_id).encode("ascii") + b" 0 R"
        if catalog_match:
            start, end = catalog_match.span()
            segment = mutated[start:end]
            if b"/OpenAction" not in segment:
                new_segment = segment[:-2] + b"\n/OpenAction " + ref + b"\n>>"
                mutated = mutated[:start] + new_segment + mutated[end:]
        else:
            catalog_obj_id = js_obj_id + 1
            catalog_object = (
                b"\n"
                + str(catalog_obj_id).encode("ascii")
                + b" 0 obj\n<< /Type /Catalog /OpenAction "
                + ref
                + b" >>\nendobj\n"
            )
            mutated = mutated + catalog_object

        insert_idx = mutated.rfind(b"startxref")
        if insert_idx == -1:
            insert_idx = len(mutated)
        return mutated[:insert_idx] + js_object + mutated[insert_idx:]

    def _corrupt_xref(self, data: bytes) -> Optional[bytes]:
        xref_idx = data.find(b"xref")
        if xref_idx == -1:
            return None
        xref_end = data.find(b"trailer", xref_idx)
        if xref_end == -1:
            xref_end = min(len(data), xref_idx + 2048)
        segment = data[xref_idx:xref_end]

        def repl(match):
            offset = random.randint(0, 9999999999)
            generation = random.randint(0, 65535)
            flag = random.choice([b"n", b"f"])
            return f"{offset:010d} {generation:05d} {flag.decode()}".encode("ascii")

        corrupted = self.entry_pattern.sub(repl, segment, count=random.randint(1, 6))
        if corrupted == segment:
            corrupted = b"xref\n9999 1\n9999999999 00000 n \n"
        return data[:xref_idx] + corrupted + data[xref_end:]

    def _truncate_or_pad(self, data: bytes) -> Optional[bytes]:
        if len(data) < 32:
            return None
        if random.random() < 0.5:
            cut = random.randint(len(data) // 3, len(data) - 8)
            return data[:cut] + b"\n%%EOF\n"
        padding = os.urandom(random.randint(64, 256))
        return data + b"\n" + padding + b"\nstartxref\n0\n%%EOF\n"

    def _incremental_update(self, data: bytes) -> Optional[bytes]:
        base = data.rstrip(b"\n")
        obj_id = self._next_object_id(base)
        payload = os.urandom(random.randint(32, 256))
        content_obj = (
            b"\n"
            + str(obj_id).encode("ascii")
            + b" 0 obj\n<< /Length "
            + str(len(payload)).encode("ascii")
            + b" >>\nstream\n"
            + payload
            + b"\nendstream\nendobj\n"
        )
        xref_offset = len(base) + len(content_obj)
        xref_block = (
            b"xref\n"
            + str(obj_id).encode("ascii")
            + b" 1\n"
            + f"{len(base):010d} 00000 n \n".encode("ascii")
        )
        trailer = (
            b"trailer\n<< /Size "
            + str(obj_id + 1).encode("ascii")
            + b" >>\nstartxref\n"
            + str(xref_offset).encode("ascii")
            + b"\n%%EOF\n"
        )
        return base + content_obj + xref_block + trailer

    def generate_mutations(self, data: bytes, count: int = 6000, monitor_seed: Optional[bytes] = None) -> List[bytes]:
        seeds = [data]
        if monitor_seed:
            seeds.append(monitor_seed)

        mutations: List[bytes] = []
        seen = set()
        attempts = 0
        max_attempts = count * 6

        while len(mutations) < count and attempts < max_attempts:
            attempts += 1
            seed = random.choice(seeds)
            strategy = random.choice(self.strategy_funcs)
            try:
                mutated = strategy(seed)
            except Exception:
                mutated = None
            if mutated and mutated != seed and mutated not in seen:
                seen.add(mutated)
                mutations.append(mutated)

        if len(mutations) < count:
            fallback_needed = count - len(mutations)
            fallback_seed = random.choice(seeds)
            fallback = self.mutator.generate_mutations(fallback_seed, count=fallback_needed)
            mutations.extend(fallback)

        return mutations[:count]


def specific_mutate(monitor_data, original_data=None):
    pdf_mutator = PDFMutator()
    monitor_bytes = _ensure_bytes(monitor_data)
    fallback_bytes = _ensure_bytes(original_data) if original_data is not None else b''

    if monitor_bytes and _looks_like_pdf(monitor_bytes):
        return pdf_mutator.generate_mutations(monitor_bytes, count=20000, monitor_seed=fallback_bytes or None)

    if fallback_bytes:
        return pdf_mutator.generate_mutations(fallback_bytes, count=20000, monitor_seed=monitor_bytes or None)

    seed = monitor_bytes or b"%PDF-1.4\n"
    return pdf_mutator.generate_mutations(seed, count=20000)


def pdf_set(data: bytes, monitor_data: Optional[bytes] = None):
    pdf_mutator = PDFMutator()
    if monitor_data:
        return specific_mutate(monitor_data, data)
    return pdf_mutator.generate_mutations(data, count=20000)
