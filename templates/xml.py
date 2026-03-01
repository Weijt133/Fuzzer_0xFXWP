from core.mutator import Mutator
import xml.etree.ElementTree as ET
import random
import copy
import string
from config.config import FUZZER_CONFIG

FUZZ_VALUES = [
    "../../../../../../../../etc/passwd",
    "<script>alert(1)</script>",
    "A" * 4096,
    "'" * 1024,
    "<![CDATA[" + "A" * 4096 + "]]>",
    "&", "\"", "<", ">",
    "%n" * 100,
    "0", "-1", "2147483647", "-2147483648",
    "1.0/0.0",
    "NULL", None,
    "../../../../../../../../windows/win.ini",
    "<img src=x onerror=alert(document.cookie)>",
    "| id", "; id", "`id`",
    "classpath:/application.properties",
    "[]", "{}",
    "\u0000"
]


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

class XMLMutator:
    def __init__(self):
        self.config = FUZZER_CONFIG.get('xml_template', {})
        self.mutator = Mutator()
        
        default_weights = {
            'mutate_content': 0.20,       
            'mutate_structure': 0.10,   
            'mutate_boundaries': 0.10,     
            'raw_flood': 0.25,             
            'deep_nested_raw': 0.05,     
            'security_payloads': 0.10,    
            'malformed_xml': 0.05,       
            'format_strings': 0.05,      
            'mutate_namespaces': 0.05,    
            'protocol_uris': 0.05          
        }

        self.strategy_weights = self.config.get('strategy_weights', default_weights)

    def _choose_strategy(self) -> str:
        rand = random.random()
        cumulative = 0
        for strategy, weight in self.strategy_weights.items():
            cumulative += weight
            if rand <= cumulative:
                return strategy
        return 'raw_flood'

    def _parse_xml(self, data):

        try:
            text = data.decode('utf-8', errors='ignore')
            return ET.fromstring(text)
        except ET.ParseError:
            return None

    def _render_xml(self, root_element):

        if not isinstance(root_element, ET.Element):
            return None
        try:
            for prefix, uri in getattr(root_element, '_namespaces', {}).items():
                ET.register_namespace(prefix, uri)
            return ET.tostring(root_element, encoding='unicode')
        except Exception:
            return None

    def _get_all_elements(self, root):
        return [elem for elem in root.iter()]

    def _random_string(self, length=8):
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

    def raw_flood(self, root):

        xml_str = self._render_xml(root)
        if not xml_str: return None

        patterns = [
            lambda tag: f"<{tag} />",
            lambda tag: f"<{tag}></{tag}>",
            lambda tag: f"<{tag} id='{random.randint(1,9999)}' />",
            lambda tag: f"<{tag} />"
        ]
        targets = ["</head>", "</body>", "</div>", "</root>", "</data>", "</a>", "</list>", "</table>"]
        
        try:
            root_tag = root.tag.split('}')[-1]
            targets.append(f"</{root_tag}>")
        except:
            pass

        target_str = None
        for t in targets:
            if t in xml_str:
                target_str = t
                break

        if not target_str:
            target_str = ">"

        count = random.choice([1000, 5000, 10000, 30000, 50000])
        
        if random.random() < 0.5:
            tag_name = "flood"
        else:
            tag_name = self._random_string(random.randint(1, 4))

        pattern_func = random.choice(patterns)
        flood_chunk = pattern_func(tag_name) * count

        try:
            if target_str == ">":
                pos = random.randint(0, len(xml_str))
                return xml_str[:pos] + flood_chunk + xml_str[pos:]
            else:
                parts = xml_str.rsplit(target_str, 1)
                if len(parts) == 2:
                    return parts[0] + flood_chunk + parts[1]
                else:
                    return xml_str + flood_chunk
        except MemoryError:
            return None
            
        return None

    def mutate_content(self, root):
        elements = self._get_all_elements(root)
        if not elements: return None
        
        modified_root = copy.deepcopy(root)
        mod_elements = [e for e in modified_root.iter()]
        if not mod_elements: return None
        
        mod_target = random.choice(mod_elements)

        if random.choice([True, False]) and mod_target.text:
            choice = random.random()
            if choice < 0.4:
                mod_target.text = random.choice(FUZZ_VALUES)
            elif choice < 0.7:
                try:
                    raw_mut = self.mutator.generate_mutations(mod_target.text.encode(), count=1)[0]
                    mod_target.text = raw_mut.decode('utf-8', errors='ignore')
                except:
                    mod_target.text = "FUZZ"
            else:
                mod_target.text += "A" * random.randint(100, 2000)
        
        if mod_target.attrib:
            if random.choice([True, False]):
                key = random.choice(list(mod_target.attrib.keys()))
                mod_target.attrib[key] = random.choice(FUZZ_VALUES)
            else:
                new_key = self._random_string(5)
                mod_target.attrib[new_key] = random.choice(FUZZ_VALUES)
            
        return modified_root

    def mutate_structure(self, root):
        elements = self._get_all_elements(root)
        if len(elements) < 2: return None

        modified_root = copy.deepcopy(root)
        parent_map = {c: p for p in modified_root.iter() for c in p}
        
        try:
            candidates = list(parent_map.keys())
            if not candidates: return None
            target = random.choice(candidates)
            parent = parent_map[target]

            action = random.choice(['delete', 'duplicate', 'shuffle', 'move'])
            
            if action == 'delete':
                parent.remove(target)
            elif action == 'duplicate':
                parent.append(copy.deepcopy(target))
            elif action == 'shuffle':
                children = list(parent)
                random.shuffle(children)
                for c in list(parent): parent.remove(c)
                for c in children: parent.append(c)
            elif action == 'move':
                parent.remove(target)
                new_parent = random.choice([e for e in modified_root.iter()])
                new_parent.append(target)
                
            return modified_root
        except Exception:
            return None

    def mutate_boundaries(self, root):
        """
        保留对象级别的变异，处理 HTML 常见结构
        """
        modified_root = copy.deepcopy(root)
        
        targets = []
        for elem in modified_root.iter():
            tag_clean = elem.tag.lower()
            if any(x in tag_clean for x in ['head', 'body', 'div', 'table', 'list']):
                targets.append(elem)
        
        target = random.choice(targets) if targets and random.random() < 0.7 else random.choice([e for e in modified_root.iter()])

        action = random.choice(['deep_nesting', 'flood_children', 'attribute_flood'])

        if action == 'deep_nesting':
            curr = target
            depth = random.randint(100, 500) 
            for i in range(depth):
                curr = ET.SubElement(curr, f"nest_{i}")
            curr.text = "end"
            
        elif action == 'flood_children':
            count = random.randint(100, 1000)
            tag_name = "child"
            for i in range(count):
                ET.SubElement(target, tag_name).text = str(i)
        
        elif action == 'attribute_flood':
            count = random.randint(100, 1000)
            for i in range(count):
                target.attrib[f'attr_{i}'] = "X" * 10

        return modified_root

    def security_payloads(self, root):
        payloads = [

            """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>""",
        
            """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>""",
      
            """<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;"><!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">]><root>&lol5;</root>""",
  
            """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]><root>&xxe;</root>""",
      
            """<a href="javascript:alert(1)">link</a>""",
            """<img src=x onerror=alert(1)>"""
        ]
        
        if random.random() < 0.6:
            return random.choice(payloads)
        
        xml_str = self._render_xml(root)
        if not xml_str: return None
        
        injection = random.choice(FUZZ_VALUES)
        if ">" in xml_str:
            parts = xml_str.split(">")
            if len(parts) > 1:
                idx = random.randint(0, len(parts)-2)
                parts[idx] += injection
                return ">".join(parts)
        return None

    def format_strings(self, root):
        modified_root = copy.deepcopy(root)
        elements = [e for e in modified_root.iter()]
        if not elements: return None
        target = random.choice(elements)
        
        fmts = ["%n", "%s", "%x", "%p", "%d", "%.10000d", "%999999$s"]
        payload = random.choice(fmts) * random.randint(1, 20)
        
        if random.choice([True, False]):
            target.text = payload
        elif target.attrib:
            key = random.choice(list(target.attrib.keys()))
            target.attrib[key] = payload
            
        return modified_root

    def malformed_xml(self, root):
        xml_str = self._render_xml(root)
        if not xml_str: return None
        
        action = random.randint(1, 5)
        if action == 1:
     
            return xml_str.replace(">", "", 1)
        elif action == 2:
       
            return xml_str[:len(xml_str)//2]
        elif action == 3:
          
            pos = random.randint(0, len(xml_str))
            return xml_str[:pos] + "\x00" + xml_str[pos:]
        elif action == 4:
          
            return xml_str.replace("UTF-8", "UTF-7", 1)
        else:
           
            return xml_str + "GARBAGE" * 10

    def mutate_namespaces(self, root):
        modified_root = copy.deepcopy(root)
        elements = [e for e in modified_root.iter()]
        if not elements: return None
        target = random.choice(elements)
        
        prefix = self._random_string(4)
        uri = f"http://{self._random_string(5)}.com"
        

        target.attrib[f'xmlns:{prefix}'] = uri

        if random.choice([True, False]):
            raw_tag = target.tag.split('}')[-1]
            target.tag = f"{prefix}:{raw_tag}"
            
        return modified_root

    def protocol_uris(self, root):
        modified_root = copy.deepcopy(root)
        elements = [e for e in modified_root.iter() if e.attrib]
        if not elements: return None
        target = random.choice(elements)
        
        uris = [
            "file:///etc/passwd", 
            "gopher://127.0.0.1:6379/_INFO",
            "expect://id",
            "php://filter/convert.base64-encode/resource=index.php",
            "http://169.254.169.254/latest/meta-data/"
        ]
        
        key = random.choice(list(target.attrib.keys()))
        target.attrib[key] = random.choice(uris)
        return modified_root

    def deep_nested_raw(self, root):
  
        xml_str = self._render_xml(root)
        if not xml_str:
            return None

        try:
            tag_name = root.tag.split('}')[-1] or "a"
        except Exception:
            tag_name = "a"


        depth = random.randint(20000, 40000)
        open_tag = f"<{tag_name}>"
        close_tag = f"</{tag_name}>"

        try:
            return open_tag * depth + xml_str + close_tag * depth
        except MemoryError:

            try:
                depth = 10000
                return open_tag * depth + xml_str + close_tag * depth
            except MemoryError:
                return None

    def _manual_string_flood(self, raw_str):
        flood_tag = random.choice(["<flood />", "<br />", "<img />", "<x>"])
        flood = flood_tag * random.randint(1000, 20000)
        
        for target in ["</head>", "</body>", "</div>"]:
            if target in raw_str:
                parts = raw_str.rsplit(target, 1)
                if len(parts) == 2:
                    return parts[0] + flood + parts[1]

        if len(raw_str) > 0:
            pos = random.randint(0, len(raw_str))
            return raw_str[:pos] + flood + raw_str[pos:]
        
        return flood

    def generate_mutations(self, data, count: int = 5000):
 
        root = self._parse_xml(data)
        
        mutations = set()
        

        if root is None:
            try:
                raw_str = data.decode('utf-8', errors='ignore')
          
                for _ in range(int(count * 0.6)):
                    res = self._manual_string_flood(raw_str)
                    if res and res not in mutations:
                        mutations.add(res)
            except:
                pass
            needed = count - len(mutations)
            if needed > 0:
                byte_muts = self.mutator.generate_mutations(data, count=needed)
                for m in byte_muts:
                    mutations.add(m.decode('utf-8', errors='ignore'))
            return list(mutations)

        original_xml = self._render_xml(root)
        if original_xml:
            mutations.add(original_xml)

        strategies = {
            'mutate_content': self.mutate_content,
            'mutate_structure': self.mutate_structure,
            'mutate_boundaries': self.mutate_boundaries,
            'raw_flood': self.raw_flood,
            'deep_nested_raw': self.deep_nested_raw,  
            'security_payloads': self.security_payloads,
            'format_strings': self.format_strings,
            'malformed_xml': self.malformed_xml,
            'mutate_namespaces': self.mutate_namespaces,
            'protocol_uris': self.protocol_uris
        }


        attempts = 0
        max_attempts = count * 5 
        
        while len(mutations) < count and attempts < max_attempts:
            attempts += 1
            strategy_name = self._choose_strategy()
            strategy_func = strategies.get(strategy_name)
            
            if not strategy_func: continue
            
            try:
                result = strategy_func(root)
                
                final_str = None
                if isinstance(result, ET.Element):
                    final_str = self._render_xml(result)
                elif isinstance(result, str):
                    final_str = result
                
                if final_str and final_str not in mutations:
                    mutations.add(final_str)
                    
            except Exception:
                continue

        if len(mutations) < count:
            needed = count - len(mutations)
            byte_muts = self.mutator.generate_mutations(data, count=needed)
            for m in byte_muts:
                mutations.add(m.decode('utf-8', errors='ignore'))

        return list(mutations)


def specific_mutate(monitor_data, original_data=None):
    xml_mutator = XMLMutator()
    monitor_bytes = _ensure_bytes(monitor_data)
    fallback_bytes = _ensure_bytes(original_data) if original_data is not None else b''

    if monitor_bytes and xml_mutator._parse_xml(monitor_bytes):
        return xml_mutator.generate_mutations(monitor_bytes, count=3000)

    if fallback_bytes and xml_mutator._parse_xml(fallback_bytes):
        return xml_mutator.generate_mutations(fallback_bytes, count=3000)

    seed = monitor_bytes or fallback_bytes
    if seed:
        return xml_mutator.generate_mutations(seed, count=3000)

    return []


def xml_set(data, monitor_data=None):

    xml_mutator = XMLMutator()
    if monitor_data:
        return specific_mutate(monitor_data, data)
    return xml_mutator.generate_mutations(data, count=3000)