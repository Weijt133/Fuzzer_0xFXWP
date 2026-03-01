from core.mutator import Mutator
import json
import random
import copy
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

class JSONMutator:
    def __init__(self):
        self.config = FUZZER_CONFIG['json_template']
        self.mutator = Mutator()
        self.strategy_weights = self.config['strategy_weights']
        self.max_mutations = self.config['max_mutations_per_strategy']

    def _choose_strategy(self) -> str:
        rand = random.random()
        cumulative = 0
        for strategy, weight in self.strategy_weights.items():
            cumulative += weight
            if rand <= cumulative:
                return strategy
        return 'mutate_values'

    def _mutate_string(self, s: str, count: int = 5) -> list:
        try:
            s_bytes = s.encode('utf-8')
            mutations = self.mutator.generate_mutations(s_bytes, count=count)
            return [m.decode('utf-8', errors='ignore') for m in mutations]
        except Exception:
            return [s]

    def _extract_items(self, obj, path="", parent=None, key_in_parent=None):
        items = []
        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else str(key)
                items.append((current_path, key, value, obj, key))
                if isinstance(value, (dict, list)):
                    items.extend(self._extract_items(value, current_path, obj, key))
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                current_path = f"{path}[{idx}]"
                items.append((current_path, idx, item, obj, idx))
                if isinstance(item, (dict, list)):
                    items.extend(self._extract_items(item, current_path, obj, idx))
        return items

    def _navigate_to_path(self, obj, path_parts):
        target = obj
        for part in path_parts:
            if '[' in part:
                base = part.split('[')[0]
                idx = int(part.split('[')[1].rstrip(']'))
                if base:
                    target = target[base]
                target = target[idx]
            else:
                target = target[part]
        return target

    def mutate_values(self, parsed):
        value_items = [item for item in self._extract_items(parsed) 
                      if isinstance(item[2], (str, int, float, bool))]
        if not value_items:
            return None

        selected = random.sample(value_items, min(1, len(value_items)))
        path, key, value, parent, key_ref = selected[0]
        
        value_mutations = self._mutate_string(str(value))
        new_value = random.choice(value_mutations)
        
        try:
            if isinstance(value, int):
                new_value = int(new_value)
            elif isinstance(value, float):
                new_value = float(new_value)
            elif isinstance(value, bool):
                new_value = new_value.lower() in ('true', '1', 'yes')
        except (ValueError, AttributeError):
            pass
        
        modified = copy.deepcopy(parsed)
        target = self._navigate_to_path(modified, path.split('.')[:-1])
        target[key_ref] = new_value
        
        return modified

    def mutate_keys(self, parsed):
        dict_items = [item for item in self._extract_items(parsed) 
                     if isinstance(item[3], dict)]
        if not dict_items:
            return None

        selected = random.sample(dict_items, min(1, len(dict_items)))
        path, key, value, parent, key_ref = selected[0]
        
        key_mutations = self._mutate_string(str(key))
        new_key = random.choice(key_mutations)
        
        modified = copy.deepcopy(parsed)
        target = self._navigate_to_path(modified, path.split('.')[:-1])
        
        if str(key) in target:
            target[new_key] = target.pop(str(key))
            return modified
        return None

    def mutate_key_value_pairs(self, parsed):
        dict_items = [item for item in self._extract_items(parsed) 
                     if isinstance(item[3], dict)]
        if not dict_items:
            return None

        selected = random.sample(dict_items, min(1, len(dict_items)))
        path, key, value, parent, key_ref = selected[0]
        
        new_key = random.choice(self._mutate_string(str(key)))
        new_value = random.choice(self._mutate_string(str(value)))
        
        modified = copy.deepcopy(parsed)
        target = self._navigate_to_path(modified, path.split('.')[:-1])
        
        if str(key) in target:
            del target[str(key)]
        
        target[new_key] = new_value
        return modified

    def add_or_delete_pairs(self, parsed):
        dict_items = [item for item in self._extract_items(parsed) 
                     if isinstance(item[3], dict)]
        if not dict_items:
            return None

        selected = random.choice(dict_items)
        path, key, value, parent, key_ref = selected
        
        modified = copy.deepcopy(parsed)
        target = self._navigate_to_path(modified, path.split('.')[:-1])
        
        if random.choice([True, False]) and str(key) in target:
            del target[str(key)]
        else:
            new_key = random.choice(self._mutate_string("new_key"))
            new_value = random.choice(self._mutate_string("new_value"))
            target[new_key] = new_value
        
        return modified

    def structure_mutation(self, parsed):
        if isinstance(parsed, list) and len(parsed) > 0:
            modified = copy.deepcopy(parsed)
            if random.choice([True, False]):
                idx = random.randint(0, len(modified)-1)
                modified.append(copy.deepcopy(modified[idx]))
            else:
                idx = random.randint(0, len(modified)-1)
                modified.pop(idx)
            return modified
        return None
    
    def add_multiple_pairs(self, parsed):

        if not isinstance(parsed, dict):
            if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                target = parsed[0]
            else:
                return None
        else:
            target = parsed
    
        modified = copy.deepcopy(parsed)

        if target is not parsed:
            modified_target = modified[0] if isinstance(modified, list) else modified
        else:
            modified_target = modified

        num_pairs = random.randint(10, self.config.get('max_pairs_to_add', 100))

        for i in range(num_pairs):
            key = f"massive_key_{i}_{random.randint(1000, 9999)}"

            value_type = random.choice(['string', 'number', 'boolean', 'null', 'nested'])

            if value_type == 'string':
                length = random.randint(10, 1000)
                value = "x" * length
            elif value_type == 'number':
                value = random.choice([
                    random.randint(-1000000, 1000000),
                    random.uniform(-1000000, 1000000),
                    0, 1, -1, 999999999, -999999999
                ])
            elif value_type == 'boolean':
                value = random.choice([True, False])
            elif value_type == 'null':
                value = None
            else:
                value = {"nested_key": f"nested_value_{i}"}

            modified_target[key] = value

        try:
            if isinstance(modified, dict):
                container = modified
            elif isinstance(modified, list) and modified and isinstance(modified[0], dict):
                container = modified[0]
            else:
                container = None

            if isinstance(container, dict) and isinstance(container.get("data"), dict):
                data_obj = container["data"]

                extra_pairs = random.randint(10, 40)
                for j in range(extra_pairs):
                    long_key = "k_" + "".join(
                        random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
                        for _ in range(random.randint(8, 32))
                    )
                    long_val = "".join(
                        random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
                        for _ in range(random.randint(80, 200))
                    )
                    data_obj[long_key] = long_val
        except Exception:
            pass

        return modified


    def add_deep_nesting(self, parsed):
        modified = copy.deepcopy(parsed)
        
        max_depth = self.config.get('max_nesting_depth', 10)
        depth = random.randint(3, max_depth)
        
        if isinstance(modified, dict):
            current = modified
            for i in range(depth):
                new_key = f"level_{i}"
                if i == depth - 1:
                    current[new_key] = f"deeply_nested_value_{random.randint(1, 100)}"
                else:
                    current[new_key] = {}
                    current = current[new_key]
        
        elif isinstance(modified, list) and modified:
            if isinstance(modified[0], dict):
                current = modified[0]
                for i in range(depth):
                    new_key = f"level_{i}"
                    if i == depth - 1:
                        current[new_key] = f"deeply_nested_value_{random.randint(1, 100)}"
                    else:
                        current[new_key] = {}
                        current = current[new_key]
        
        return modified
    
    def generate_mutations(self, data, count: int = 1000):
        try:
            parsed = json.loads(data.decode('utf-8', errors='ignore'))
        except json.JSONDecodeError:
            return [data]
        
        mutations = set()
        original_json = json.dumps(parsed, ensure_ascii=False)
        
        strategies = {
            'mutate_values': self.mutate_values,
            'mutate_keys': self.mutate_keys,
            'mutate_key_value_pairs': self.mutate_key_value_pairs,
            'add_or_delete_pairs': self.add_or_delete_pairs,
            'structure_mutation': self.structure_mutation,
            'add_multiple_pairs': self.add_multiple_pairs,
            'add_deep_nesting': self.add_deep_nesting
        }
        
        attempts = 0
        max_attempts = count * 3
        
        while len(mutations) < count and attempts < max_attempts:
            attempts += 1
            strategy_name = self._choose_strategy()
            strategy_func = strategies[strategy_name]
            
            try:
                result = strategy_func(parsed)
                if result and result != parsed:
                    mutated_json = json.dumps(result, ensure_ascii=False)
                    if mutated_json != original_json:
                        mutations.add(mutated_json)
            except Exception:
                continue
        
        if len(mutations) < count:
            byte_mutations = self.mutator.generate_mutations(
                data, count=count - len(mutations)
            )
            for mutation in byte_mutations:
                try:
                    parsed_mut = json.loads(mutation.decode('utf-8', errors='ignore'))
                    mutations.add(json.dumps(parsed_mut, ensure_ascii=False))
                except:
                    pass
        
        return list(mutations)[:count]


def specific_mutate(monitor_data, original_data=None):
    json_mutator = JSONMutator()

    def _is_valid(payload):
        if not payload:
            return False
        try:
            json.loads(payload.decode('utf-8', errors='ignore'))
            return True
        except Exception:
            return False

    monitor_bytes = _ensure_bytes(monitor_data)
    fallback_bytes = _ensure_bytes(original_data) if original_data is not None else b''

    if monitor_bytes and _is_valid(monitor_bytes):
        return json_mutator.generate_mutations(monitor_bytes, count=5000)

    if fallback_bytes and _is_valid(fallback_bytes):
        return json_mutator.generate_mutations(fallback_bytes, count=5000)

    seed = monitor_bytes or fallback_bytes
    if seed:
        return json_mutator.generate_mutations(seed, count=5000)

    return []


def json_set(data, monitor_data=None):
    json_mutator = JSONMutator()
    if monitor_data:
        return specific_mutate(monitor_data, data)
    
    return json_mutator.generate_mutations(data, count=5000)
