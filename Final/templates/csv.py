from core.mutator import Mutator
from core.monitor import Monitor
from config.config import FUZZER_CONFIG
import csv
import io
import random



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


def specific_mutate(monitor_data, original_data=None):
    csv_cfg = FUZZER_CONFIG.get('csv_template', {})
    monitor_bytes = _ensure_bytes(monitor_data)
    fallback_bytes = _ensure_bytes(original_data) if original_data is not None else b''

    parsed = parse_csv(monitor_bytes) if monitor_bytes else []
    if not parsed and fallback_bytes:
        parsed = parse_csv(fallback_bytes)

    if parsed:
        return mutate(parsed, csv_cfg)

    base = monitor_bytes or fallback_bytes
    if not base:
        return []

    mutator = Mutator()
    count = csv_cfg.get('max_cases', 500)
    try:
        byte_muts = mutator.generate_mutations(base, count=count)
        return [m.decode('utf-8', errors='ignore') for m in byte_muts]
    except Exception:
        return [base.decode('utf-8', errors='ignore')]


def parse_csv(data):
    try:
        text = data.decode('utf-8', errors='ignore')
    except Exception:
        return []

    rows = []
    try:
        reader = csv.reader(io.StringIO(text))
        for row in reader:
            rows.append(["" if c is None else str(c) for c in row])
    except Exception:
        return []
    return rows


def _render_csv(rows, delimiter=','):
    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=delimiter, lineterminator='\n', quoting=csv.QUOTE_MINIMAL)
    writer.writerows(rows)
    return buffer.getvalue()


def csv_set(data, monitor_data=None):
    parsed = parse_csv(data)
    csv_cfg = FUZZER_CONFIG.get('csv_template', {})
    max_cases = csv_cfg.get('max_cases', 5000)

    if monitor_data:
        mutated_data_list = specific_mutate(monitor_data, data)
        return mutated_data_list[:max_cases]

    mutated_data_list = mutate(parsed, csv_cfg)

    if not mutated_data_list:
        try:
            mutated_data_list = [_render_csv(parsed)] if parsed else [data.decode('utf-8', errors='ignore')]
        except Exception:
            mutated_data_list = [data.decode('utf-8', errors='ignore')]

    return mutated_data_list[:max_cases]


def mutate(parsed, csv_cfg=None):
    if not parsed:
        return []

    mutator = Mutator()
    results = []
    seen = set()
    csv_cfg = csv_cfg or {}
    max_cases = csv_cfg.get('max_cases', 500)
    mutations_per_cell = csv_cfg.get('mutations_per_cell', 2)
    mutations_per_row = csv_cfg.get('mutations_per_row', 2)
    whole_file_mutations = csv_cfg.get('whole_file_mutations', 200)
    take_from_whole_file = csv_cfg.get('take_from_whole_file', 50)

    def add_result(text):
        if not isinstance(text, str):
            return
        if text not in seen:
            seen.add(text)
            results.append(text)

    def mutate_string(s, count=1000):
        try:
            s_bytes = s.encode('utf-8')
            mutations = mutator.generate_mutations(s_bytes, count=count)
            return [m.decode('utf-8', errors='ignore') for m in mutations]
        except Exception:
            return [s]

    max_cols = max((len(r) for r in parsed), default=0)
    all_cells = []
    for ri, row in enumerate(parsed):
        for ci, _ in enumerate(row):
            all_cells.append((ri, ci))

    def mutate_cells():
        if not all_cells:
            return
        n = min(random.randint(1, 5), len(all_cells))
        selected = random.sample(all_cells, n)
        for ri, ci in selected:
            base = parsed[ri][ci]
            candidates = mutate_string(base)
            for nv in candidates[:mutations_per_cell]:
                mod = [list(r) for r in parsed]
                mod[ri][ci] = nv
                add_result(_render_csv(mod))

    def mutate_rows():
        if not parsed:
            return
        row_indices = list(range(len(parsed)))
        if not row_indices:
            return

        r_sel = random.sample(row_indices, min(len(row_indices), random.randint(1, 3)))
        for ri in r_sel:
            row_text = ','.join(parsed[ri])
            for v in mutate_string(row_text)[:mutations_per_row]:
                mod = [list(r) for r in parsed]
                mod[ri] = v.split(',')
                add_result(_render_csv(mod))

        if len(parsed) > 1 and random.choice([True, False]):
            del_count = random.randint(1, min(3, len(parsed) - 1))
            del_rows = set(random.sample(row_indices, del_count))
            mod = [list(r) for i, r in enumerate(parsed) if i not in del_rows]
            add_result(_render_csv(mod))

        if random.choice([True, False]):
            ri = random.choice(row_indices)
            mod = [list(r) for r in parsed]
            mod.insert(ri, list(parsed[ri]))
            add_result(_render_csv(mod))

    def mutate_columns():
        if max_cols == 0:
            return
        col_idx = random.randint(0, max_cols - 1)

        if random.choice([True, False]):
            mod = []
            for row in parsed:
                if len(row) > col_idx:
                    nr = list(row)
                    del nr[col_idx]
                    mod.append(nr)
                else:
                    mod.append(list(row))
            add_result(_render_csv(mod))

        base_vals = mutate_string("new_value")[:2]
        for base in base_vals:
            mod = []
            for row in parsed:
                nr = list(row)
                insert_at = min(col_idx, len(nr))
                nr.insert(insert_at, base)
                mod.append(nr)
            add_result(_render_csv(mod))

    def shuffle_rows_cols():
        mod = [list(r) for r in parsed]
        random.shuffle(mod)
        add_result(_render_csv(mod))

        if max_cols > 1:
            order = list(range(max_cols))
            random.shuffle(order)
            mod = []
            for row in parsed:
                padded = list(row) + [""] * (max_cols - len(row))
                mod.append([padded[i] for i in order])
            add_result(_render_csv(mod))

    def delimiter_and_quote():
        text = _render_csv(parsed)
        for d in [';', '\t', '|']:
            add_result(_render_csv(parsed, delimiter=d))

        if text:
            corrupted = text.replace(",", '",', 1)
            add_result(corrupted)
            corrupted = text.replace(",", ',"', 1)
            add_result(corrupted)
            corrupted = '"' + text
            add_result(corrupted)

    def whole_file_mutations():
        text = _render_csv(parsed)
        try:
            data = text.encode('utf-8')
            muts = mutator.generate_mutations(data, count=whole_file_mutations)
            for m in muts[:take_from_whole_file]:
                add_result(m.decode('utf-8', errors='ignore'))
        except Exception:
            pass

    def keep_header_and_expand_last_field():
        if len(parsed) < 2:
            return
        header = list(parsed[0])
        sample_row = list(parsed[1]) if len(parsed) > 1 else list(parsed[0])
        if not sample_row:
            return

        repeat_count = random.randint(10, 40)
        mod = [header]
        for _ in range(repeat_count):
            mod.append(list(sample_row))

        last = list(sample_row)
        last_col_idx = max(0, len(last) - 1)
        base = last[last_col_idx] if last else ""
        base = base if base else 'a'
        amplified = base * 10000
        last[last_col_idx] = amplified
        mod.append(last)

        add_result(_render_csv(mod))

    def targeted_parser_edge_cases():
        if not parsed:
            return
        header = list(parsed[0])
        try:
            many_cols_count = 5000
            row_many_cols = ["x"] * many_cols_count
            add_result(_render_csv([header, row_many_cols]))
        except Exception:
            pass
        try:
            long_unclosed = '"' + ('A' * 200000)
            row_unclosed = list(parsed[1]) if len(parsed) > 1 else (header + ["x"])[:max(1, len(header))]
            if len(row_unclosed) < max_cols:
                row_unclosed += [""] * (max_cols - len(row_unclosed))
            if row_unclosed:
                row_unclosed[-1] = long_unclosed
            add_result(_render_csv([header, row_unclosed]))
        except Exception:
            pass

        try:
            nul_payload = ("A" * 1000) + "\x00" + ("B" * 1000) + "\xff" * 400
            row_nul = ["A", "B", "C", nul_payload]
            add_result(_render_csv([header, row_nul]))
        except Exception:
            pass

        try:
            big_int = str(2**63 - 1)
            neg_big = str(-(2**63))
            row_ints = [big_int, neg_big, "999999999999999999999999", "-999999999999999999999999"]
            add_result(_render_csv([header, row_ints]))
        except Exception:
            pass

        try:
            long_field = 'Z' * (1024 * 1024 + 20000)
            row_long = ["a", "b", "c", long_field]
            text = _render_csv([header, row_long])
            add_result(text.rstrip('\n'))
        except Exception:
            pass

        try:
            mix_cols = ["\x00" + ('"' + ('Q' * 50000))] + ["y"] * 4000
            add_result(_render_csv([header, mix_cols]))
        except Exception:
            pass

        try:
            long_tail = 'a' * (1024 * 1024 + 100000)
            row_like_sample = ["i", "j", "k", long_tail]
            add_result(_render_csv([header, row_like_sample]))
        except Exception:
            pass
        try:
            tail = 'a' * 200000
            row = ["i", "j", "k", tail]
            block = [header] + [row for _ in range(300)]
            add_result(_render_csv(block))
        except Exception:
            pass

        try:
            short_tail = 'a' * 7
            long_tail = 'a' * (1024 * 1024 + 400000)
            short_row = ["i", "j", "k", short_tail]
            long_row = ["i", "j", "k", long_tail]
            block = [header] + [short_row for _ in range(200)] + [long_row]
            add_result(_render_csv(block))
        except Exception:
            pass

    try:
        targeted_parser_edge_cases()
        mutate_cells()
        mutate_rows()
        mutate_columns()
        shuffle_rows_cols()
        delimiter_and_quote()
        whole_file_mutations()
        keep_header_and_expand_last_field()
    except Exception:
        pass

    if len(results) < max_cases:
        try:
            base = _render_csv(parsed).encode('utf-8')
            need = max_cases - len(results)
            extra = Mutator().generate_mutations(base, count=need)
            for m in extra:
                add_result(m.decode('utf-8', errors='ignore'))
        except Exception:
            pass

    return results[:max_cases]


