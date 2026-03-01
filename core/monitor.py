import copy
import signal
import time


class Monitor:
    def __init__(self, termination_conditions=None):
        self.signal_names = {
            signal.SIGSEGV: "SIGSEGV (Segmentation Fault)",
            signal.SIGILL: "SIGILL (Illegal Instruction)",
            signal.SIGABRT: "SIGABRT (Abort)",
            signal.SIGFPE: "SIGFPE (Floating Point Exception)",
            signal.SIGBUS: "SIGBUS (Bus Error)"
        }
        
        self.coverage_tracker = {}
        self.termination_conditions = copy.deepcopy(termination_conditions or {})
        if 'signals' not in self.termination_conditions:
            self.termination_conditions['signals'] = []
        if 'signal_output_combinations' not in self.termination_conditions:
            self.termination_conditions['signal_output_combinations'] = {}
    
    def get_signal_name(self, sig_num):
        return self.signal_names.get(sig_num, f"Unknown Signal ({sig_num})")
    
    def monitor(self, process, stdout=b'', stderr=b'', coverage=None, input_data=None):
        if process is None:
            return {
                'exit_code': None,
                'signal': None,
                'coverage': None,
                'stdout': stdout,
                'stderr': stderr,
                'crash_detected': False
            }
        
        try:

            process.wait(timeout=1)
            exit_code = process.returncode
            signal_info = self.get_exit_signal(exit_code)
            coverage_info = None
            if coverage is not None:
                coverage_info = self.collect_coverage(input_data, coverage)
            crash_detected = self.detect_crash(exit_code, stderr)
            
            return {
                'exit_code': exit_code,
                'signal': signal_info,
                'coverage': coverage_info,
                'stdout': stdout,
                'stderr': stderr,
                'crash_detected': crash_detected
            }
        except Exception as e:
            process.kill()
            return {
                'exit_code': None,
                'signal': str(e),
                'coverage': None,
                'stdout': stdout,
                'stderr': stderr,
                'crash_detected': False
            }
    
    def get_exit_signal(self, return_code):
        if return_code is None or return_code >= 0:
            return None  
        
        sig_num = -return_code
        return self.get_signal_name(sig_num)
    
    def collect_coverage(self, input_data, coverage):
        coverage_data = coverage.run(input_data)
        if coverage_data is not None:
            return coverage_data
        return None

    def detect_crash(self, exit_code, stderr):
        if exit_code is None or exit_code >= 0:
            return False

        sig_num = -exit_code
        signals = self.termination_conditions.get('signals', [])
        if sig_num in signals:
            return True

        signal_patterns = self.termination_conditions.get('signal_output_combinations', {})
        stderr_data = self._normalize_stderr(stderr)
        for pattern in signal_patterns.get(sig_num, []):
            if pattern in stderr_data:
                return True
        return False

    def _normalize_stderr(self, stderr):
        if isinstance(stderr, bytes):
            return stderr.lower()
        if stderr:
            try:
                return str(stderr).encode().lower()
            except Exception:
                return b''
        return b''

if __name__ == "__main__":
    monitor = Monitor()
    print(monitor.get_signal_name(signal.SIGSEGV))