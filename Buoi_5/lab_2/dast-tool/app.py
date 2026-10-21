import os
import subprocess
import psutil
from flask import Flask, jsonify, request
from runtime_monitor import RuntimeMonitor
from memory_analyzer import MemoryAnalyzer
from network_traffic_analyzer import NetworkTrafficAnalyzer
from security_behavior_checker import SecurityBehaviorChecker
from virtual_sandbox import VirtualSandbox

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 8192


@app.get('/api/monitor')
def monitor():
    rm = RuntimeMonitor(os.getpid())
    return jsonify(cpu_usage=rm.get_cpu_usage(),
                   memory_usage=rm.get_memory_usage(),
                   open_files=[f.path for f in rm.get_open_files()])


@app.get('/api/memory')
def memory():
    ma = MemoryAnalyzer()
    return jsonify(memory_leaks=str(ma.check_memory_leaks()),
                   overflow_test=ma.check_overflow(2**64))


@app.get('/api/network')
def network():
    stats = NetworkTrafficAnalyzer().get_network_stats()
    return jsonify(network_stats={k: v._asdict() for k, v in stats.items()})


@app.get('/api/security')
def security():
    return jsonify(suspicious_calls=SecurityBehaviorChecker().suspicious_calls(),
                   analysis_mode='source_text_heuristic')


@app.post('/api/sandbox')
def sandbox():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error='Expected a JSON object with command'), 400
    try:
        with VirtualSandbox() as vs:
            stdout, stderr = vs.run_isolated(data.get('command'))
        return jsonify(stdout=stdout, stderr=stderr)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    except subprocess.TimeoutExpired:
        return jsonify(error='Demo command timed out'), 504
    except subprocess.CalledProcessError:
        return jsonify(error='Demo command failed'), 500


@app.errorhandler(psutil.Error)
def process_error(exc):
    return jsonify(error=type(exc).__name__), 503


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
