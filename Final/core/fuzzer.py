import os
import subprocess
import signal
import importlib
import time
from tqdm import tqdm
from core.recognizer import Recognizer
from core.monitor import Monitor
from core.coverage import Coverage
from config.config import FUZZER_CONFIG

class Fuzzer:
    def __init__(self):
        self.config = FUZZER_CONFIG
        self.recognizer = Recognizer()
        self.monitor = Monitor(self.config.get('termination_conditions', {}))
        self.current_processes = {}
        self.mime_type_mapping = self.config.get('mime_type_mapping', {})
        self.crash_records = {}
        coverage_cfg = self.config.get('coverage', {})
        self.coverage_threshold = max(0.0, coverage_cfg.get('improvement_threshold', 0.0))
        self.coverage_enabled = coverage_cfg.get('enabled', False)
        self.binary_timeout = max(0, self.config.get('binary_timeout_seconds', 0))
        self.test_case_timeout = max(1, self.config.get('test_case_timeout_seconds', 1))
    
    def get_input_binary_pairs(self):
        input_path = self.config['path']['input_path']
        binary_path = self.config['path']['binary_path']
        pairs = []
        for input_file in os.listdir(input_path):
            name, ext = os.path.splitext(input_file)
            binary_file = os.path.join(binary_path, name)
            if os.path.exists(binary_file):
                pairs.append((os.path.join(input_path, input_file), binary_file))
        return pairs
    
    def run_binary_with_input(self, binary_path, input_data, coverage, timeout=1):
        process_id = f"{binary_path}_{hash(input_data) & 0xFFFFFF}"
        
        try:
            process = subprocess.Popen(
                binary_path, 
                stdin=subprocess.PIPE, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )
            
            self.current_processes[process_id] = {
                'process': process,
                'binary_path': binary_path,
                'input_data': input_data
            }
            
            try:
                stdout, stderr = process.communicate(input=input_data, timeout=timeout)
                
                monitoring_result = self.monitor.monitor(
                    process,
                    stdout,
                    stderr,
                    coverage,
                    input_data
                )
                
                crash_detected = monitoring_result.get('crash_detected', False)

                if crash_detected:
                    self.record_crash(binary_path, monitoring_result, input_data)
                    output_dir = self.config['path']['output_path']
                    os.makedirs(output_dir, exist_ok=True)
                    bad_input_path = os.path.join(output_dir, f"bad_{os.path.basename(binary_path)}.txt")
                    with open(bad_input_path, 'wb') as f:
                        f.write(input_data)
                    self.terminate_related_processes(binary_path)
                
                return monitoring_result
                
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                return {
                    'exit_code': None,
                    'signal': "TIMEOUT",
                    'coverage': None,
                    'stdout': stdout,
                    'stderr': stderr,
                    'crash_detected': False
                }
        except Exception as e:
            return {
                'exit_code': None,
                'signal': str(e),
                'coverage': None,
                'stdout': b'',
                'stderr': b'',
                'crash_detected': False
            }
        finally:
            if process_id in self.current_processes:
                del self.current_processes[process_id]
    
    def terminate_related_processes(self, binary_path):
        processes_to_terminate = []
        
        for process_id, process_info in self.current_processes.items():
            if process_info['binary_path'] == binary_path:
                processes_to_terminate.append(process_id)
        
        for process_id in processes_to_terminate:
            process_info = self.current_processes[process_id]
            try:
                process_info['process'].terminate()
            except:
                try:
                    process_info['process'].kill()
                except:
                    pass
            finally:
                if process_id in self.current_processes:
                    del self.current_processes[process_id]
    
    def _ensure_bytes(self, data):
        if isinstance(data, bytes):
            return data
        if isinstance(data, bytearray):
            return bytes(data)
        if isinstance(data, str):
            return data.encode(errors='ignore')
        return bytes(data)

    def _generate_data_list(self, template_fn, seed_data, monitor_seed=None):
        if monitor_seed is not None:
            regenerated = template_fn(seed_data, monitor_seed) or []
            if regenerated:
                return regenerated
        return template_fn(seed_data) or []

    def test_binary(self, binary_path, template_module, template_type, content):
        results = []
        
        coverage = None
        if self.coverage_enabled:
            coverage = Coverage(binary_path)
            if not coverage.blocks:
                coverage.discover()
            
        template_fn = getattr(template_module, f"{template_type}_set")
        seed_data = content
        data_list = self._generate_data_list(template_fn, seed_data)
        best_coverage = None
        start_time = time.time()
        timeout_hit = False

        while data_list:
            progress_bar = tqdm(
                data_list,
                desc=f"Testing {os.path.basename(binary_path)}",
                unit="input",
                ncols=100
            )
            restart_requested = False

            for data in progress_bar:
                if self.binary_timeout and time.time() - start_time >= self.binary_timeout:
                    progress_bar.set_description(
                        f"Testing {os.path.basename(binary_path)} - TIMEOUT"
                    )
                    print(
                        f"\n[!] Skipping {binary_path} after {self.binary_timeout}s without completion"
                    )
                    timeout_hit = True
                    restart_requested = False
                    break

                payload = self._ensure_bytes(data)
                progress_bar.set_description(f"Testing {os.path.basename(binary_path)}")

                result = self.run_binary_with_input(binary_path, payload, coverage, self.test_case_timeout)
                results.append({
                    'data': payload,
                    'exit_code': result['exit_code'],
                    'signal': result['signal'],
                    'coverage': result['coverage'],
                    'stdout': result['stdout'],
                    'stderr': result['stderr'],
                    'crash_detected': result.get('crash_detected', False)
                })


                
                coverage_value = result.get('coverage')
                # print(coverage_value)
                if (
                    coverage_value is not None
                    and best_coverage is not None
                    and self.coverage_threshold > 0
                    and coverage_value - best_coverage >= self.coverage_threshold
                ):
                    data_list = self._generate_data_list(template_fn, seed_data, payload)
                    print(f"\n[+] Coverage improved for {binary_path}: {best_coverage} -> {coverage_value}")
                    best_coverage = coverage_value
                    restart_requested = True
                    break

                if coverage_value is not None:
                    if best_coverage is None or coverage_value > best_coverage:
                        best_coverage = coverage_value
                if result.get('crash_detected'):
                    progress_bar.set_description(
                        f"Testing {os.path.basename(binary_path)} - CRASHED"
                    )
                    print(f"\n[!] Early termination for {binary_path} due to critical issue")
                    restart_requested = False
                    break

            progress_bar.close()

            if timeout_hit:
                break

            if restart_requested:
                continue
            break
                
        return results

    def record_crash(self, binary_path, monitoring_result, input_data):
        if not binary_path:
            return
        crash_entry = {
            'exit_code': monitoring_result.get('exit_code'),
            'signal': monitoring_result.get('signal'),
            'stderr': monitoring_result.get('stderr'),
            'stdout': monitoring_result.get('stdout'),
            'input_data': input_data,
            'coverage': monitoring_result.get('coverage')
        }
        self.crash_records.setdefault(binary_path, []).append(crash_entry)
    
    def process_input_binary_pair(self, input_path, binary_path):
        template_type, content = self.recognizer.recognize(input_path)
        
        try:
            template_module = importlib.import_module(f"templates.{template_type}")
            return self.test_binary(binary_path, template_module, template_type, content)
        except (ImportError, AttributeError) as e:
            print(f"[!] Error loading template for {template_type}: {e}")
            return None
    
    
    def fuzz(self):
        input_binary_pairs = self.get_input_binary_pairs()
        
        if not input_binary_pairs:
            print("[!] No valid input-binary pairs found")
            return
        
        all_results = []
        for input_path, binary_path in input_binary_pairs:
            print(f"[*] Processing {binary_path} with input {input_path}")
            result = self.process_input_binary_pair(input_path, binary_path)
            if result:
                all_results.append((binary_path, result))
        
        self.report_results(all_results)
    
    def report_results(self, all_results):
        for binary_path, results in all_results:
            print(f"\n[+] Results for {os.path.basename(binary_path)}:")
            crashes = self.crash_records.get(binary_path, [])
            
            if crashes:
                print(f"  Found {len(crashes)} crashes:")
                for crash in crashes:
                    print(f"  - Exit code: {crash['exit_code']}, Signal: {crash['signal']}")
                    if crash['exit_code'] == -signal.SIGABRT and crash.get('stderr'):
                        print("  - Stderr: "+ crash['stderr'].decode(errors='ignore').strip())
                    input_preview = (crash.get('input_data') or b'')[:100]
                    print(f"  - Input data (first 100 bytes): {input_preview}...")
                    if crash.get('coverage'):
                        print(f"    Coverage: {crash['coverage']}")
            else:
                print("  No crashes detected.")

if __name__ == "__main__":
    fuzzer = Fuzzer()
    fuzzer.fuzz()