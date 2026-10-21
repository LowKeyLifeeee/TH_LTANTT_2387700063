import os
from runtime_monitor import RuntimeMonitor
from memory_analyzer import MemoryAnalyzer
from network_traffic_analyzer import NetworkTrafficAnalyzer
from security_behavior_checker import SecurityBehaviorChecker
from virtual_sandbox import VirtualSandbox


def main():
    print('[+] Monitoring current process:', os.getpid())
    rm = RuntimeMonitor(os.getpid())
    print('CPU Usage (%):', rm.get_cpu_usage())
    print('Memory Usage (bytes):', rm.get_memory_usage())
    print('Open Files:', rm.get_open_files())
    ma = MemoryAnalyzer()
    print('Memory leaks (GC heuristic):', ma.check_memory_leaks())
    print('Overflow Test (signed int64):', ma.check_overflow(2**64))
    print('Network Stats:', NetworkTrafficAnalyzer().get_network_stats())
    print('Suspicious Calls (source heuristic, not runtime evidence):',
          SecurityBehaviorChecker().suspicious_calls())
    with VirtualSandbox() as sandbox:
        out, err = sandbox.run_isolated('echo Hello Sandbox')
        print('Sandbox stdout:', out.strip())
        print('Sandbox stderr:', err)


if __name__ == '__main__':
    main()
