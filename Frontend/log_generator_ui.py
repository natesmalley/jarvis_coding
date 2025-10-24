import os
import subprocess
import json
import socket
import requests
from flask import Flask, render_template, request, jsonify, Response, stream_with_context
import sys
import uuid
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import queue
import logging

app = Flask(__name__)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

EVENT_GENERATORS_DIR = os.path.join(os.getcwd(), 'event_generators')
API_BASE_URL = os.environ.get('API_BASE_URL', 'http://localhost:8000')
BACKEND_API_KEY = os.environ.get('BACKEND_API_KEY')

@app.route('/')
def index():
    return render_template('log_generator.html')

def get_scripts():
    scripts = {}
    try:
        if not os.path.exists(EVENT_GENERATORS_DIR):
            return scripts
        for root, dirs, files in os.walk(EVENT_GENERATORS_DIR):
            py_files = sorted([f for f in files if f.endswith('.py')])
            if py_files:
                relative_root = os.path.relpath(root, EVENT_GENERATORS_DIR)
                if relative_root == '.':
                    category_name = "Uncategorized"
                else:
                    category_name = relative_root.replace(os.sep, ' - ').title()
                scripts[category_name] = [os.path.join(relative_root, f) for f in py_files]
    except Exception as e:
        print(f"Error scanning for scripts: {e}")
    return scripts

def _get_api_headers():
    """Get headers for backend API requests"""
    headers = {}
    if BACKEND_API_KEY:
        headers['X-API-Key'] = BACKEND_API_KEY
    return headers

def fetch_generators():
    base_url = f"{API_BASE_URL}/api/v1/generators"
    try:
        headers = {'X-API-Key': BACKEND_API_KEY} if BACKEND_API_KEY else None
        all_items = []
        # First try to request a large page to avoid pagination
        resp = requests.get(base_url, params={'page': 1, 'per_page': 500}, headers=headers, timeout=20)
        if resp.status_code == 200:
            payload = resp.json()
            data = payload.get('data', {})
            all_items = data.get('generators', [])
        else:
            # Fallback to default pagination loop
            page = 1
            total_pages = 1
            while page <= total_pages:
                resp = requests.get(base_url, params={'page': page}, headers=headers, timeout=20)
                if resp.status_code != 200:
                    # If we already have some items, return them rather than hard-fail
                    if all_items:
                        break
                    return None, f"Backend returned {resp.status_code}: {resp.text}"
                payload = resp.json()
                data = payload.get('data', {})
                items = data.get('generators', [])
                all_items.extend(items)
                meta = payload.get('metadata', {})
                pagination = meta.get('pagination', {})
                total_pages = int(pagination.get('total_pages', total_pages)) or 1
                page += 1

        # Simplify for dropdown: list of {id, name, category, file_path}
        simplified = [
            {
                'id': g.get('id'),
                'name': g.get('name'),
                'category': g.get('category'),
                'file_path': g.get('file_path')
            }
            for g in all_items
        ]
        return simplified, None
    except Exception as e:
        return None, str(e)

@app.route('/get-generators', methods=['GET'])
def get_generators():
    data, err = fetch_generators()
    if err:
        return jsonify({'error': f'Failed to fetch generators from backend: {err}'}), 502
    return jsonify({'generators': data})

@app.route('/destinations', methods=['GET'])
def list_destinations():
    """List destinations from backend API"""
    try:
        resp = requests.get(
            f"{API_BASE_URL}/api/v1/destinations",
            headers=_get_api_headers(),
            timeout=10
        )
        if resp.status_code == 200:
            destinations = resp.json()
            return jsonify({'destinations': destinations})
        else:
            logger.error(f"Backend returned {resp.status_code}: {resp.text}")
            return jsonify({'error': f'Backend error: {resp.status_code}'}), resp.status_code
    except Exception as e:
        logger.error(f"Failed to fetch destinations: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/destinations', methods=['POST'])
def create_destination():
    """Create destination via backend API"""
    payload = request.get_json(silent=True) or {}
    
    logger.info(f"Creating destination: type={payload.get('type')}, name={payload.get('name')}")
    
    try:
        resp = requests.post(
            f"{API_BASE_URL}/api/v1/destinations",
            json=payload,
            headers=_get_api_headers(),
            timeout=10
        )
        
        if resp.status_code == 201:
            return jsonify(resp.json()), 201
        else:
            error_detail = resp.json().get('detail', resp.text) if resp.headers.get('content-type') == 'application/json' else resp.text
            logger.error(f"Backend returned {resp.status_code}: {error_detail}")
            return jsonify({'error': error_detail}), resp.status_code
    except Exception as e:
        logger.error(f"Failed to create destination: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/destinations/<dest_id>', methods=['DELETE'])
def delete_destination(dest_id: str):
    """Delete destination via backend API"""
    try:
        resp = requests.delete(
            f"{API_BASE_URL}/api/v1/destinations/{dest_id}",
            headers=_get_api_headers(),
            timeout=10
        )
        
        if resp.status_code == 204:
            return ('', 204)
        else:
            error_detail = resp.json().get('detail', resp.text) if resp.headers.get('content-type') == 'application/json' else resp.text
            logger.error(f"Backend returned {resp.status_code}: {error_detail}")
            return jsonify({'error': error_detail}), resp.status_code
    except Exception as e:
        logger.error(f"Failed to delete destination: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/scenarios', methods=['GET'])
def list_scenarios():
    """List available attack scenarios"""
    scenarios = [
        {
            'id': 'attack_scenario_orchestrator',
            'name': 'Operation Digital Heist',
            'description': 'Sophisticated 14-day APT campaign against a financial services company. Simulates reconnaissance, initial access, persistence, privilege escalation, and data exfiltration.',
            'duration_days': 14,
            'events_per_day': 50,
            'total_events': 700,
            'phases': ['Reconnaissance & Phishing', 'Initial Access', 'Persistence & Lateral Movement', 'Privilege Escalation', 'Data Exfiltration']
        },
        {
            'id': 'enterprise_attack_scenario',
            'name': 'Enterprise Breach Scenario',
            'description': 'Enhanced enterprise attack scenario with 330+ events across multiple security products. Demonstrates correlated attack patterns.',
            'duration_minutes': 60,
            'total_events': 330,
            'phases': ['Initial Compromise', 'Credential Harvesting', 'Lateral Movement', 'Privilege Escalation', 'Data Exfiltration', 'Persistence']
        },
        {
            'id': 'enterprise_attack_scenario_10min',
            'name': 'Enterprise Breach (10 min)',
            'description': 'Condensed enterprise breach scenario for quick demos.',
            'duration_minutes': 10,
            'total_events': 120,
            'phases': ['Initial Access', 'Lateral Movement', 'Exfiltration']
        },
        {
            'id': 'enterprise_scenario_sender',
            'name': 'Enterprise Scenario Sender (330+ events)',
            'description': 'Sends enhanced enterprise attack scenario events to HEC using proper routing.',
            'duration_minutes': 45,
            'total_events': 330,
            'phases': ['Initial Compromise', 'Credential Harvesting', 'Lateral Movement', 'Privilege Escalation', 'Data Exfiltration']
        },
        {
            'id': 'enterprise_scenario_sender_10min',
            'name': 'Enterprise Scenario Sender (10 min)',
            'description': 'Fast sender for enterprise scenario suitable for time-boxed demos.',
            'duration_minutes': 10,
            'total_events': 120,
            'phases': ['Initial Access', 'Lateral Movement', 'Exfiltration']
        },
        {
            'id': 'showcase_attack_scenario',
            'name': 'AI-SIEM Showcase Scenario',
            'description': 'Showcase scenario demonstrating multi-platform correlation across EDR, Email, Identity, Cloud, Network, WAF, and more.',
            'duration_minutes': 30,
            'total_events': 200,
            'phases': ['Phishing', 'Compromise', 'Movement', 'Privilege Escalation', 'Exfiltration']
        },
        {
            'id': 'showcase_scenario_sender',
            'name': 'Showcase Scenario Sender',
            'description': 'Sends the showcase scenario events to HEC with compact progress output.',
            'duration_minutes': 20,
            'total_events': 180,
            'phases': ['Phishing', 'Compromise', 'Movement', 'Exfiltration']
        },
        {
            'id': 'quick_scenario',
            'name': 'Quick Scenario (Comprehensive)',
            'description': 'Generates a compact yet comprehensive attack scenario spanning multiple sources.',
            'duration_minutes': 5,
            'total_events': 80,
            'phases': ['Initial Access', 'Reconnaissance', 'Movement', 'Exfiltration']
        },
        {
            'id': 'quick_scenario_simple',
            'name': 'Quick Scenario (Simple)',
            'description': 'Minimal scenario for smoke testing pipeline and parsers.',
            'duration_minutes': 2,
            'total_events': 30,
            'phases': ['Access', 'Movement']
        },
        {
            'id': 'scenario_hec_sender',
            'name': 'Scenario HEC Sender',
            'description': 'Generic scenario sender that replays a scenario JSON to HEC.',
            'duration_minutes': 15,
            'total_events': 150,
            'phases': ['Replay']
        },
        {
            'id': 'star_trek_integration_test',
            'name': 'Integration Test (Star Trek)',
            'description': 'Integration test scenario for end-to-end validation and fun output.',
            'duration_minutes': 3,
            'total_events': 20,
            'phases': ['Test']
        }
    ]
    return jsonify({'scenarios': scenarios})

@app.route('/scenarios/run', methods=['POST'])
def run_scenario():
    """Execute a scenario and stream progress"""
    data = request.json
    scenario_id = data.get('scenario_id')
    destination_id = data.get('destination_id')
    worker_count = int(data.get('workers', 10))  # Default 10 parallel workers
    
    if not scenario_id:
        return jsonify({'error': 'scenario_id is required'}), 400
    if not destination_id:
        return jsonify({'error': 'destination_id is required'}), 400
    
    # Resolve destination from backend API
    try:
        dest_resp = requests.get(
            f"{API_BASE_URL}/api/v1/destinations/{destination_id}",
            headers=_get_api_headers(),
            timeout=10
        )
        if dest_resp.status_code != 200:
            return jsonify({'error': 'Destination not found'}), 404
        
        chosen = dest_resp.json()
        
        if chosen.get('type') != 'hec':
            return jsonify({'error': 'Scenarios currently only support HEC destinations'}), 400
        
        # Build HEC URL based on destination format
        endpoint_format = chosen.get('endpoint_format', 'full_url')
        if endpoint_format == 'ip_port':
            host = chosen.get('host')
            port = chosen.get('port')
            use_https = chosen.get('use_https', True)
            protocol = 'https' if use_https else 'http'
            hec_url = f"{protocol}://{host}:{port}/services/collector"
        else:
            hec_url = chosen.get('url')
        
        # Fetch decrypted token from backend
        token_resp = requests.get(
            f"{API_BASE_URL}/api/v1/destinations/{destination_id}/token",
            headers=_get_api_headers(),
            timeout=10
        )
        if token_resp.status_code != 200:
            return jsonify({'error': 'Failed to retrieve HEC token'}), 400
        
        hec_token = token_resp.json().get('token')
        
        if not hec_url or not hec_token:
            return jsonify({'error': 'HEC destination incomplete or token missing'}), 400
    except Exception as e:
        logger.error(f"Failed to resolve destination: {e}")
        return jsonify({'error': f'Failed to resolve destination: {str(e)}'}), 500
    
    def generate_and_stream():
        try:
            yield "INFO: Starting scenario execution...\n"
            # Map scenario ids to filenames when they differ
            id_to_file = {
                'attack_scenario_orchestrator': 'attack_scenario_orchestrator.py',
                'enterprise_attack_scenario': 'enterprise_attack_scenario.py',
                'enterprise_attack_scenario_10min': 'enterprise_attack_scenario_10min.py',
                'enterprise_scenario_sender': 'enterprise_scenario_sender.py',
                'enterprise_scenario_sender_10min': 'enterprise_scenario_sender_10min.py',
                'showcase_attack_scenario': 'showcase_attack_scenario.py',
                'showcase_scenario_sender': 'showcase_scenario_sender.py',
                'quick_scenario': 'quick_scenario.py',
                'quick_scenario_simple': 'quick_scenario_simple.py',
                'scenario_hec_sender': 'scenario_hec_sender.py',
                'star_trek_integration_test': 'star_trek_integration_test.py',
            }
            scenarios_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Backend', 'scenarios'))
            # Resolve script path
            filename = id_to_file.get(scenario_id, f"{scenario_id}.py")
            script_path = os.path.join(scenarios_dir, filename)
            if not os.path.exists(script_path):
                yield f"ERROR: Scenario script not found: {filename}\n"
                return

            # Prepare environment for HEC sender used by scenario scripts
            env = os.environ.copy()
            env['S1_HEC_TOKEN'] = hec_token
            # Set both EVENT and RAW base URLs to prevent fallback to defaults
            hec_base = hec_url.rstrip('/')
            if not hec_base.endswith('/services/collector'):
                hec_base = hec_base + '/services/collector'
            env['S1_HEC_EVENT_URL_BASE'] = hec_base + '/event'
            env['S1_HEC_RAW_URL_BASE'] = hec_base + '/raw'
            env['S1_HEC_URL'] = hec_base  # Keep for backward compatibility
            env['S1_HEC_WORKERS'] = str(worker_count)  # Pass worker count to scripts
            env['S1_HEC_BATCH'] = '0'  # Disable batch mode for immediate responses
            
            # Add event generators and all category subdirectories to Python path
            event_generators_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Backend', 'event_generators'))
            
            # Build list of all category directories
            python_paths = [event_generators_dir]
            categories = ['cloud_infrastructure', 'network_security', 'endpoint_security', 
                         'identity_access', 'email_security', 'web_security', 'infrastructure', 'shared']
            for category in categories:
                category_path = os.path.join(event_generators_dir, category)
                if os.path.exists(category_path):
                    python_paths.append(category_path)
            
            # Set PYTHONPATH
            existing_pythonpath = env.get('PYTHONPATH', '')
            pythonpath_str = ':'.join(python_paths)
            if existing_pythonpath:
                env['PYTHONPATH'] = f"{pythonpath_str}:{existing_pythonpath}"
            else:
                env['PYTHONPATH'] = pythonpath_str
            
            logger.info(f"Set PYTHONPATH with {len(python_paths)} directories")

            yield f"INFO: Executing {filename} with {worker_count} parallel workers...\n"
            import subprocess
            process = subprocess.Popen(
                ['python', script_path],
                cwd=scenarios_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env
            )

            # Stream output lines
            for line in iter(process.stdout.readline, ''):
                if not line:
                    break
                yield line

            process.wait()
            rc = process.returncode
            if rc == 0:
                yield "INFO: Scenario execution complete\n"
            else:
                yield f"ERROR: Scenario exited with code {rc}\n"
        except Exception as e:
            yield f"ERROR: Scenario execution failed: {e}\n"
    
    return Response(stream_with_context(generate_and_stream()), mimetype='text/plain')

@app.route('/get-scripts', methods=['GET'])
def get_available_scripts():
    scripts = get_scripts()
    if not scripts:
        return jsonify({"message": "No log scripts found."}), 404
    return jsonify(scripts)

@app.route('/generate-logs', methods=['POST'])
def generate_logs():
    data = request.json
    destination = data.get('destination', 'syslog')
    script_path = data.get('script')
    log_count = int(data.get('count', 3))
    eps = float(data.get('eps', 1.0))
    syslog_ip = data.get('ip')
    syslog_port = int(data.get('port')) if data.get('port') is not None else None
    syslog_protocol = data.get('protocol')
    product_id = data.get('product')
    # Unified destination id (preferred)
    unified_dest_id = data.get('destination_id')
    # Back-compat fields
    hec_dest_id = data.get('hec_destination_id')
    syslog_dest_id = data.get('syslog_destination_id')
    
    if destination == 'syslog':
        full_script_path = os.path.join(EVENT_GENERATORS_DIR, script_path)
        if not os.path.exists(full_script_path):
            return jsonify({'error': 'Invalid script name or path'}), 400

    def generate_and_stream():
        sock = None
        try:
            if destination == 'syslog':
                # Resolve syslog destination if provided
                resolved_syslog_id = unified_dest_id if unified_dest_id else syslog_dest_id
                if resolved_syslog_id:
                    try:
                        dest_resp = requests.get(
                            f"{API_BASE_URL}/api/v1/destinations/{resolved_syslog_id}",
                            headers=_get_api_headers(),
                            timeout=10
                        )
                        if dest_resp.status_code != 200 or dest_resp.json().get('type') != 'syslog':
                            yield "ERROR: Selected syslog destination not found.\n"
                            return
                        chosen = dest_resp.json()
                        syslog_ip_local = chosen.get('ip')
                        syslog_port_local = int(chosen.get('port') or 0)
                        syslog_protocol_local = (chosen.get('protocol') or '').upper()
                    except Exception as e:
                        yield f"ERROR: Failed to resolve syslog destination: {e}\n"
                        return
                else:
                    syslog_ip_local = syslog_ip
                    syslog_port_local = syslog_port
                    syslog_protocol_local = (syslog_protocol or '').upper()

                if not syslog_ip_local or not syslog_port_local or syslog_protocol_local not in ('UDP','TCP'):
                    yield "ERROR: Missing or invalid syslog destination details.\n"
                    return

                if syslog_protocol_local == 'UDP':
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                elif syslog_protocol_local == 'TCP':
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        sock.connect((syslog_ip_local, syslog_port_local))
                    except Exception as e:
                        yield f"ERROR: Could not connect to TCP syslog server at {syslog_ip_local}:{syslog_port_local}. Details: {e}\n"
                        return
                else:
                    yield "ERROR: Invalid syslog protocol. Please select TCP or UDP.\n"
                    return

                yield "INFO: Starting log generation...\n"

                command = ['python', full_script_path, str(log_count)]
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                for line in iter(process.stdout.readline, ''):
                    if line:
                        log_line = line.strip()
                        try:
                            if syslog_protocol_local == 'UDP':
                                sock.sendto(bytes(log_line + '\n', 'utf-8'), (syslog_ip_local, syslog_port_local))
                            else:
                                sock.sendall(bytes(log_line + '\n', 'utf-8'))
                        except Exception as e:
                            yield f"ERROR: Failed to send log to syslog server. Details: {e}\n"
                            process.terminate()
                            break

                        yield f"LOG: {log_line}\n"

                errors = process.stderr.read()
                if errors:
                    yield f"ERROR: Script execution produced errors:\n{errors}\n"

                process.wait()

            elif destination == 'hec':
                # Validate inputs
                if not product_id:
                    yield "ERROR: Missing product id for HEC.\n"
                    return

                # Resolve destination from backend API
                resolved_hec_id = unified_dest_id if unified_dest_id else hec_dest_id
                
                try:
                    if resolved_hec_id:
                        # Get specific destination
                        dest_resp = requests.get(
                            f"{API_BASE_URL}/api/v1/destinations/{resolved_hec_id}",
                            headers=_get_api_headers(),
                            timeout=10
                        )
                        if dest_resp.status_code != 200 or dest_resp.json().get('type') != 'hec':
                            yield "ERROR: Selected HEC destination not found.\n"
                            return
                        chosen = dest_resp.json()
                    else:
                        # Get first HEC destination
                        list_resp = requests.get(
                            f"{API_BASE_URL}/api/v1/destinations",
                            headers=_get_api_headers(),
                            timeout=10
                        )
                        if list_resp.status_code != 200:
                            yield "ERROR: Failed to fetch destinations from backend.\n"
                            return
                        destinations = list_resp.json()
                        hec_dests = [d for d in destinations if d.get('type') == 'hec']
                        if not hec_dests:
                            yield "ERROR: No HEC destination configured. Add one in Settings > Destinations.\n"
                            return
                        chosen = hec_dests[0]
                    
                    # Build HEC URL based on destination format
                    endpoint_format = chosen.get('endpoint_format', 'full_url')
                    if endpoint_format == 'ip_port':
                        host = chosen.get('host')
                        port = chosen.get('port')
                        use_https = chosen.get('use_https', True)
                        protocol = 'https' if use_https else 'http'
                        hec_url = f"{protocol}://{host}:{port}/services/collector"
                    else:
                        hec_url = chosen.get('url')
                    
                    dest_id = chosen.get('id')
                    
                    # Fetch decrypted token from backend
                    token_resp = requests.get(
                        f"{API_BASE_URL}/api/v1/destinations/{dest_id}/token",
                        headers=_get_api_headers(),
                        timeout=10
                    )
                    if token_resp.status_code != 200:
                        yield "ERROR: Failed to retrieve HEC token from backend.\n"
                        return
                    
                    hec_token = token_resp.json().get('token')
                    
                    if not hec_url or not hec_token:
                        yield "ERROR: Selected HEC destination is incomplete or token missing.\n"
                        return
                    
                    logger.info(f"Resolved HEC destination: id={dest_id}, url={hec_url}")
                except Exception as e:
                    logger.error(f"Failed to resolve HEC destination: {e}", exc_info=True)
                    yield f"ERROR: Failed to resolve HEC destination: {e}\n"
                    return

                yield f"INFO: Starting HEC send to {hec_url}...\n"
                yield f"INFO: Sending {log_count} events for product '{product_id}' at {eps} EPS\n"

                # Build path to hec_sender.py (Frontend/../Backend/event_generators/shared/hec_sender.py)
                hec_sender_path = os.path.normpath(
                    os.path.join(os.path.dirname(__file__), '..', 'Backend', 'event_generators', 'shared', 'hec_sender.py')
                )
                if not os.path.exists(hec_sender_path):
                    yield "ERROR: HEC sender not found.\n"
                    return

                # Normalize HEC URL: accept bare domain and append collector path
                def _normalize_hec_url(u: str) -> str:
                    if not u:
                        return u
                    base = u.rstrip('/')
                    if base.endswith('/event') or base.endswith('/raw'):
                        return base
                    # If already includes /services/collector, keep it
                    if '/services/collector' in base:
                        return base
                    return base + '/services/collector'

                normalized_hec_url = _normalize_hec_url(hec_url)
                logger.info(f"Normalized HEC URL: {normalized_hec_url}")

                env = os.environ.copy()
                env['S1_HEC_TOKEN'] = hec_token
                # Set both EVENT and RAW base URLs to prevent fallback to defaults
                env['S1_HEC_EVENT_URL_BASE'] = normalized_hec_url + '/event'
                env['S1_HEC_RAW_URL_BASE'] = normalized_hec_url + '/raw'
                env['S1_HEC_URL'] = normalized_hec_url  # Keep for backward compatibility
                # Disable batch mode to get immediate HTTP responses
                env['S1_HEC_BATCH'] = '0'
                # Enable debug output to see exact payloads
                env['S1_HEC_DEBUG'] = '1'

                # Calculate delay from EPS: delay = 1 / eps
                delay = 1.0 / eps if eps > 0 else 1.0
                command = ['python3', hec_sender_path, '--product', product_id, '-n', str(log_count), 
                           '--min-delay', str(delay), '--max-delay', str(delay), '--print-responses']
                logger.info(f"Executing HEC sender: {' '.join(command)}")
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=env
                )

                # Stream sanitized output
                line_count = 0
                for line in iter(process.stdout.readline, ''):
                    if not line:
                        break
                    line_count += 1
                    # Redact token from output
                    sanitized = line.replace(hec_token, '***REDACTED***')
                    yield sanitized
                    logger.debug(f"HEC sender output line {line_count}: {sanitized.strip()}")

                # Capture any errors or additional output
                process.wait()
                stderr_output = process.stderr.read() if process.stderr else ""
                logger.info(f"HEC sender process completed with return code: {process.returncode}")
                
                if stderr_output:
                    sanitized_stderr = stderr_output.replace(hec_token, '***REDACTED***')
                    logger.info(f"HEC sender stderr: {sanitized_stderr}")
                    # Show stderr output (may contain debug info)
                    if sanitized_stderr.strip():
                        yield f"DEBUG: {sanitized_stderr}\n"
                
                if process.returncode != 0:
                    logger.error(f"HEC send failed with return code {process.returncode}")
                    yield f"ERROR: HEC send failed with code {process.returncode}\n"
                else:
                    yield f"INFO: Successfully sent {log_count} events to HEC\n"
                    logger.info(f"Successfully sent {log_count} events")

        except FileNotFoundError:
            yield f"ERROR: Python executable not found. Please ensure Python is in your system's PATH.\n"
        except Exception as e:
            yield f"ERROR: An unexpected error occurred: {e}\n"
            
        finally:
            logger.info("Log generation complete")
            yield "INFO: Log generation complete.\n"
            if sock:
                sock.close()

    return Response(stream_with_context(generate_and_stream()), mimetype='text/plain')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)

