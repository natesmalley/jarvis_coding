import os
import subprocess
import json
import csv
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

@app.route('/test-token-storage')
def test_token_storage():
    """Token storage test page"""
    return render_template('test_token_storage.html')

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
        
        # Retry logic for API startup
        max_retries = 5
        retry_delay = 2
        for attempt in range(max_retries):
            try:
                # First try to request a large page to avoid pagination
                resp = requests.get(base_url, params={'page': 1, 'per_page': 500}, headers=headers, timeout=10)
                break  # Success, exit retry loop
            except requests.exceptions.RequestException as e:
                if attempt < max_retries - 1:
                    logger.warning(f"API not ready (attempt {attempt + 1}/{max_retries}), retrying in {retry_delay}s...")
                    time.sleep(retry_delay)
                    retry_delay *= 1.5  # Exponential backoff
                else:
                    raise  # Re-raise on final attempt
        
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
def delete_destination(dest_id):
    """Delete a destination"""
    try:
        response = requests.delete(
            f"{API_BASE_URL}/api/v1/destinations/{dest_id}",
            headers=_get_api_headers(),
            timeout=10
        )
        return Response(status=response.status_code)
    except Exception as e:
        logger.error(f"Failed to delete destination: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/destinations/<dest_id>/update-token', methods=['POST'])
def update_destination_token(dest_id):
    """Update token for a destination in the database"""
    try:
        data = request.json
        token = data.get('token')
        
        if not token:
            return jsonify({'error': 'Token is required'}), 400
        
        # Update the destination with new token
        response = requests.put(
            f"{API_BASE_URL}/api/v1/destinations/{dest_id}",
            headers=_get_api_headers(),
            json={'token': token},
            timeout=10
        )
        
        if response.status_code == 200:
            logger.info(f"Updated token for destination: {dest_id}")
            return jsonify({'message': 'Token updated successfully'})
        else:
            return jsonify({'error': f'Backend returned {response.status_code}'}), response.status_code
            
    except Exception as e:
        logger.error(f"Failed to update destination token: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/destinations/<dest_id>', methods=['PUT'])
def update_destination(dest_id):
    """Update destination fields"""
    try:
        data = request.json or {}
        
        payload = {}
        if data.get('name'):
            payload['name'] = data['name']
        if data.get('url'):
            payload['url'] = data['url']
        if data.get('token'):
            payload['token'] = data['token']
        if data.get('config_api_url'):
            payload['config_api_url'] = data['config_api_url']
        if data.get('config_read_token'):
            payload['config_read_token'] = data['config_read_token']
        if data.get('config_write_token'):
            payload['config_write_token'] = data['config_write_token']
        
        if not payload:
            return jsonify({'error': 'No fields provided to update'}), 400
        
        response = requests.put(
            f"{API_BASE_URL}/api/v1/destinations/{dest_id}",
            headers=_get_api_headers(),
            json=payload,
            timeout=10
        )
        
        if response.status_code == 200:
            logger.info(f"Updated destination: {dest_id}")
            return jsonify(response.json())
        else:
            error_text = response.text
            logger.error(f"Backend returned {response.status_code}: {error_text}")
            return jsonify({'error': f'Backend returned {response.status_code}'}), response.status_code
            
    except Exception as e:
        logger.error(f"Failed to update destination: {e}")
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
            'id': 'enterprise_scenario_sender',
            'name': 'Enterprise Attack Scenario',
            'description': 'Enhanced enterprise attack scenario with 330+ events across 18+ security platforms. Generates and sends events to HEC.',
            'duration_minutes': 45,
            'total_events': 330,
            'phases': ['Perimeter Breach', 'Phishing & Initial Access', 'Credential Harvesting', 'Lateral Movement', 'Privilege Escalation', 'Persistence & Exfiltration']
        },
        {
            'id': 'showcase_scenario_sender',
            'name': 'AI-SIEM Showcase Scenario',
            'description': 'Showcase scenario demonstrating multi-platform correlation across EDR, Email, Identity, Cloud, Network, WAF, and more.',
            'duration_minutes': 20,
            'total_events': 180,
            'phases': ['Perimeter Attack', 'Cloud Reconnaissance', 'Identity Compromise', 'Email Attack', 'Endpoint Compromise', 'Secrets Access', 'MFA Bypass']
        },
        {
            'id': 'enterprise_scenario_sender_10min',
            'name': 'Enterprise Breach (10 min)',
            'description': 'Condensed enterprise breach scenario for quick demos. Generates and sends events to HEC.',
            'duration_minutes': 10,
            'total_events': 120,
            'phases': ['Perimeter Breach', 'Credential Harvesting', 'Lateral Movement', 'Privilege Escalation']
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
            'id': 'finance_mfa_fatigue_scenario',
            'name': 'Finance Employee MFA Fatigue Attack',
            'description': 'Baseline (Days 1-7), MFA fatigue from Russia, OneDrive exfiltration, SOAR detections and automated response.',
            'duration_days': 8,
            'total_events': 135,
            'phases': ['Normal Behavior', 'MFA Fatigue', 'Initial Access', 'Data Exfiltration', 'Detection & Response']
        },
        {
            'id': 'insider_cloud_download_exfiltration',
            'name': 'Insider Data Exfiltration via Cloud Download',
            'description': 'Insider threat scenario: anomalous large-volume M365/SharePoint downloads (180+ files), DLP classification, and removable USB media copying. Correlates Okta, M365 UAL, DLP, and EDR.',
            'duration_days': 8,
            'total_events': 280,
            'phases': ['Baseline', 'Off-Hours Access', 'Cloud Download Spike', 'USB Copy', 'Detection']
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
    
    # Filter out hidden scenarios
    try:
        headers = {'X-API-Key': BACKEND_API_KEY} if BACKEND_API_KEY else {}
        res = requests.get(f"{API_BASE_URL}/api/v1/settings/hidden-scenarios", headers=headers, timeout=5)
        if res.status_code == 200:
            hidden = res.json().get('hidden_scenarios', [])
            scenarios = [s for s in scenarios if s['id'] not in hidden]
    except Exception as e:
        logger.warning(f"Could not fetch hidden scenarios: {e}")
    
    return jsonify({'scenarios': scenarios})


@app.route('/api/v1/settings/hidden-scenarios', methods=['GET'])
def get_hidden_scenarios():
    """Proxy to get hidden scenarios from backend"""
    try:
        headers = {'X-API-Key': BACKEND_API_KEY} if BACKEND_API_KEY else {}
        res = requests.get(f"{API_BASE_URL}/api/v1/settings/hidden-scenarios", headers=headers, timeout=5)
        return jsonify(res.json()), res.status_code
    except Exception as e:
        logger.error(f"Failed to get hidden scenarios: {e}")
        return jsonify({'hidden_scenarios': []}), 200


@app.route('/scenarios/all', methods=['GET'])
def list_all_scenarios():
    """List ALL scenarios without filtering hidden ones - for settings UI"""
    scenarios = [
        {'id': 'attack_scenario_orchestrator', 'name': 'Operation Digital Heist'},
        {'id': 'enterprise_scenario_sender', 'name': 'Enterprise Attack Scenario'},
        {'id': 'showcase_scenario_sender', 'name': 'AI-SIEM Showcase Scenario'},
        {'id': 'enterprise_scenario_sender_10min', 'name': 'Enterprise Breach (10 min)'},
        {'id': 'quick_scenario', 'name': 'Quick Scenario (Comprehensive)'},
        {'id': 'quick_scenario_simple', 'name': 'Quick Scenario (Simple)'},
        {'id': 'finance_mfa_fatigue_scenario', 'name': 'Finance Employee MFA Fatigue Attack'},
        {'id': 'insider_cloud_download_exfiltration', 'name': 'Insider Data Exfiltration via Cloud Download'},
        {'id': 'scenario_hec_sender', 'name': 'Scenario HEC Sender'},
        {'id': 'star_trek_integration_test', 'name': 'Integration Test (Star Trek)'}
    ]
    return jsonify(scenarios)


@app.route('/api/v1/settings/hidden-scenarios', methods=['PUT'])
def set_hidden_scenarios():
    """Proxy to set hidden scenarios in backend"""
    try:
        headers = {'X-API-Key': BACKEND_API_KEY, 'Content-Type': 'application/json'} if BACKEND_API_KEY else {'Content-Type': 'application/json'}
        res = requests.put(
            f"{API_BASE_URL}/api/v1/settings/hidden-scenarios",
            headers=headers,
            json=request.json,
            timeout=5
        )
        return jsonify(res.json()), res.status_code
    except Exception as e:
        logger.error(f"Failed to set hidden scenarios: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/settings/parser-repositories', methods=['GET'])
def get_parser_repositories():
    """Proxy to get parser GitHub repositories from backend"""
    try:
        headers = {'X-API-Key': BACKEND_API_KEY} if BACKEND_API_KEY else {}
        res = requests.get(f"{API_BASE_URL}/api/v1/settings/parser-repositories", headers=headers, timeout=5)
        return jsonify(res.json()), res.status_code
    except Exception as e:
        logger.error(f"Failed to get parser repositories: {e}")
        return jsonify({'repositories': []}), 200


@app.route('/api/v1/settings/parser-repositories', methods=['PUT'])
def set_parser_repositories():
    """Proxy to set parser GitHub repositories in backend"""
    try:
        headers = {'X-API-Key': BACKEND_API_KEY, 'Content-Type': 'application/json'} if BACKEND_API_KEY else {'Content-Type': 'application/json'}
        res = requests.put(
            f"{API_BASE_URL}/api/v1/settings/parser-repositories",
            headers=headers,
            json=request.json,
            timeout=5
        )
        return jsonify(res.json()), res.status_code
    except Exception as e:
        logger.error(f"Failed to set parser repositories: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/parser-sync/github/search', methods=['POST'])
def search_github_parsers():
    """Proxy to search for parsers in GitHub repositories"""
    try:
        headers = {'X-API-Key': BACKEND_API_KEY, 'Content-Type': 'application/json'} if BACKEND_API_KEY else {'Content-Type': 'application/json'}
        res = requests.post(
            f"{API_BASE_URL}/api/v1/parser-sync/github/search",
            headers=headers,
            json=request.json,
            timeout=30
        )
        return jsonify(res.json()), res.status_code
    except Exception as e:
        logger.error(f"Failed to search GitHub parsers: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/parser-sync/github/fetch', methods=['POST'])
def fetch_github_parser():
    """Proxy to fetch parser content from GitHub"""
    try:
        headers = {'X-API-Key': BACKEND_API_KEY, 'Content-Type': 'application/json'} if BACKEND_API_KEY else {'Content-Type': 'application/json'}
        res = requests.post(
            f"{API_BASE_URL}/api/v1/parser-sync/github/fetch",
            headers=headers,
            json=request.json,
            timeout=30
        )
        return jsonify(res.json()), res.status_code
    except Exception as e:
        logger.error(f"Failed to fetch GitHub parser: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/parser-sync/github/list', methods=['GET'])
def list_github_repo_parsers():
    """Proxy to list parsers in a GitHub repository"""
    try:
        headers = {'X-API-Key': BACKEND_API_KEY} if BACKEND_API_KEY else {}
        repo_url = request.args.get('repo_url', '')
        github_token = request.args.get('github_token', '')
        res = requests.get(
            f"{API_BASE_URL}/api/v1/parser-sync/github/list",
            headers=headers,
            params={'repo_url': repo_url, 'github_token': github_token},
            timeout=30
        )
        return jsonify(res.json()), res.status_code
    except Exception as e:
        logger.error(f"Failed to list GitHub parsers: {e}")
        return jsonify({'error': str(e)}), 500


# Track running scenario process for stop functionality
_running_scenario_process = None
_running_scenario_lock = threading.Lock()

@app.route('/scenarios/stop', methods=['POST'])
def stop_scenario():
    """Stop the currently running scenario"""
    global _running_scenario_process
    with _running_scenario_lock:
        if _running_scenario_process and _running_scenario_process.poll() is None:
            try:
                import signal
                # Try graceful termination first
                _running_scenario_process.terminate()
                try:
                    _running_scenario_process.wait(timeout=2)
                except:
                    # Force kill if it doesn't respond
                    _running_scenario_process.kill()
                logger.info("Scenario process terminated by user")
                return jsonify({'status': 'stopped'})
            except Exception as e:
                logger.error(f"Failed to stop scenario: {e}")
                return jsonify({'error': str(e)}), 500
        return jsonify({'status': 'no_process_running'})

@app.route('/scenarios/run', methods=['POST'])
def run_scenario():
    """Execute a scenario and stream progress"""
    data = request.json
    scenario_id = data.get('scenario_id')
    destination_id = data.get('destination_id')
    worker_count = int(data.get('workers', 10))  # Default 10 parallel workers
    tag_phase = data.get('tag_phase', True)
    tag_trace = data.get('tag_trace', True)
    trace_id = (data.get('trace_id') or '').strip()
    generate_noise = data.get('generate_noise', False)
    noise_events_count = int(data.get('noise_events_count', 1200))
    local_token = data.get('hec_token')  # Token from browser localStorage
    sync_parsers = data.get('sync_parsers', True)  # Enable parser sync by default
    debug_mode = data.get('debug_mode', False)  # Verbose logging mode
    
    if not scenario_id:
        return jsonify({'error': 'scenario_id is required'}), 400
    if not destination_id:
        return jsonify({'error': 'destination_id is required'}), 400
    
    # Resolve destination from backend API
    config_read_token = None
    config_write_token = None
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
        
        hec_url = chosen.get('url')
        
        # Use local token if provided, otherwise fetch from backend
        if local_token:
            hec_token = local_token
            logger.info(f"Using local token from browser for destination: {destination_id}")
        else:
            # Fetch decrypted token from backend as fallback
            token_resp = requests.get(
                f"{API_BASE_URL}/api/v1/destinations/{destination_id}/token",
                headers=_get_api_headers(),
                timeout=10
            )
            if token_resp.status_code != 200:
                return jsonify({'error': 'Failed to retrieve HEC token. Please set a local token in Settings.'}), 400
            
            hec_token = token_resp.json().get('token')
            logger.info(f"Using backend token for destination: {destination_id}")
        
        if not hec_url or not hec_token:
            return jsonify({'error': 'HEC destination incomplete or token missing'}), 400
        
        # Fetch config token and URL for parser sync if available
        config_api_url = chosen.get('config_api_url')
        config_write_token = None
        github_repo_urls = []
        github_token = None
        if sync_parsers and chosen.get('has_config_write_token') and config_api_url:
            try:
                config_resp = requests.get(
                    f"{API_BASE_URL}/api/v1/destinations/{destination_id}/config-tokens",
                    headers=_get_api_headers(),
                    timeout=10
                )
                if config_resp.status_code == 200:
                    config_tokens = config_resp.json()
                    config_write_token = config_tokens.get('config_write_token')
                    logger.info(f"Retrieved config token for parser sync (API URL: {config_api_url})")
            except Exception as ce:
                logger.warning(f"Failed to retrieve config token: {ce}")
            
            # Fetch GitHub parser repositories from settings
            try:
                repos_resp = requests.get(
                    f"{API_BASE_URL}/api/v1/settings/parser-repositories",
                    headers=_get_api_headers(),
                    timeout=10
                )
                if repos_resp.status_code == 200:
                    repos_data = repos_resp.json()
                    github_repo_urls = [url for url in repos_data.get('repositories', []) if url]
                    github_token = repos_data.get('github_token')
                    if github_repo_urls:
                        logger.info(f"Retrieved {len(github_repo_urls)} GitHub parser repositories")
            except Exception as ge:
                logger.warning(f"Failed to retrieve GitHub parser repositories: {ge}")
    except Exception as e:
        logger.error(f"Failed to resolve destination: {e}")
        return jsonify({'error': f'Failed to resolve destination: {str(e)}'}), 500
    
    def generate_and_stream():
        try:
            yield "INFO: Starting scenario execution...\n"
            
            # Parser sync: Check and upload required parsers before running scenario
            if sync_parsers and config_write_token and config_api_url:
                yield "INFO: Checking required parsers in destination SIEM...\n"
                try:
                    # Call the parser sync API with GitHub repos
                    sync_payload = {
                        "scenario_id": scenario_id,
                        "config_api_url": config_api_url,
                        "config_write_token": config_write_token
                    }
                    if github_repo_urls:
                        sync_payload["github_repo_urls"] = github_repo_urls
                    if github_token:
                        sync_payload["github_token"] = github_token
                    
                    sync_resp = requests.post(
                        f"{API_BASE_URL}/api/v1/parser-sync/sync",
                        headers=_get_api_headers(),
                        json=sync_payload,
                        timeout=120
                    )
                    if sync_resp.status_code == 200:
                        sync_result = sync_resp.json()
                        for source, info in sync_result.get('results', {}).items():
                            status = info.get('status', 'unknown')
                            message = info.get('message', '')
                            if status == 'exists':
                                yield f"INFO: Parser exists: {source}\n"
                            elif status == 'uploaded':
                                yield f"INFO: Parser uploaded: {source}\n"
                            elif status == 'failed':
                                yield f"WARN: Parser sync failed: {source} - {message}\n"
                            elif status == 'no_parser':
                                yield f"WARN: No parser mapping: {source}\n"
                        yield "INFO: Parser sync complete\n"
                    else:
                        yield f"WARN: Parser sync API returned {sync_resp.status_code}, continuing without sync\n"
                except Exception as pe:
                    yield f"WARN: Parser sync failed: {pe}, continuing without sync\n"
            elif sync_parsers:
                yield "INFO: Parser sync skipped (missing config_api_url or config tokens for destination)\n"
            
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
                'finance_mfa_fatigue_scenario': 'finance_mfa_fatigue_scenario.py',
                'insider_cloud_download_exfiltration': 'insider_cloud_download_exfiltration.py',
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
            # Ensure proper URL format for HEC sender
            clean_url = hec_url.rstrip('/')
            if '/services/collector' not in clean_url:
                clean_url = clean_url + '/services/collector'
            env['S1_HEC_URL'] = clean_url
            yield f"INFO: Using HEC URL: {clean_url}\n"
            yield f"INFO: Debug mode: {'ON' if debug_mode else 'OFF'}\n"
            env['S1_HEC_WORKERS'] = str(worker_count)  # Pass worker count to scripts
            env['S1_HEC_BATCH'] = '0'  # Disable batch mode for immediate responses
            # Prefer a writable location inside the container for scenario outputs
            env['SCENARIO_OUTPUT_DIR'] = '/app/data/scenarios/configs'
            # Control inclusion of scenario.phase tag via env
            env['S1_TAG_PHASE'] = '1' if tag_phase else '0'
            # Control inclusion of scenario.trace_id tag via env
            env['S1_TAG_TRACE'] = '1' if tag_trace else '0'
            if trace_id:
                env['S1_TRACE_ID'] = trace_id
            
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
            
            # Output filtering function for non-debug mode
            import re
            important_patterns = [
                re.compile(r'^[🚀🎯📊🔗✅❌⚠️📅🔍⬆️📤🚪🔒💾📁📈👤💻🔑]'),  # Emoji prefixes
                re.compile(r'Phase:|Trace ID:|scenario complete|SCENARIO|Campaign|events generated|Success Rate', re.IGNORECASE),
                re.compile(r'^INFO:|^WARN:|^ERROR:|^DEBUG:'),
                re.compile(r'Sending \d+ events|Replaying|transmission complete|Progress:', re.IGNORECASE),
                re.compile(r'Total Events:|Compromised|Stolen|Summary', re.IGNORECASE),
                re.compile(r'^\s*$'),  # Empty lines (for formatting)
            ]
            
            def should_output_line(line: str) -> bool:
                """Return True if line should be shown in non-debug mode"""
                if debug_mode:
                    return True
                stripped = line.strip()
                if not stripped:
                    return False
                # Skip verbose debug lines (payload dumps, etc)
                if stripped.startswith('[DEBUG]'):
                    return False
                # Always show errors
                if '❌' in stripped or 'ERROR' in stripped or 'Failed' in stripped:
                    return True
                return any(p.search(stripped) for p in important_patterns)

            yield f"INFO: Executing {filename} with {worker_count} parallel workers...\n"
            import subprocess
            
            # Build command with appropriate flags
            cmd = ['python', script_path]
            # Add --non-interactive flag for scripts that support it
            if scenario_id == 'attack_scenario_orchestrator':
                cmd.extend(['--non-interactive', '--retroactive'])
            
            global _running_scenario_process
            process = subprocess.Popen(
                cmd,
                cwd=scenarios_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env
            )
            # Track the process for stop functionality
            with _running_scenario_lock:
                _running_scenario_process = process

            # Stream output lines (filtered in non-debug mode)
            for line in iter(process.stdout.readline, ''):
                if not line:
                    break
                if should_output_line(line):
                    yield line

            process.wait()
            rc = process.returncode
            if rc == 0:
                yield "INFO: Scenario generation complete\n"
                # If this scenario produces a JSON file, automatically replay it to HEC
                try:
                    if scenario_id in ['finance_mfa_fatigue_scenario', 'insider_cloud_download_exfiltration', 'attack_scenario_orchestrator']:
                        from os import path
                        output_dir = env.get('SCENARIO_OUTPUT_DIR', path.join(scenarios_dir, 'configs'))
                        output_file = path.join(output_dir, f'{scenario_id}.json')
                        if not path.exists(output_file):
                            # Fallback to scenarios/configs
                            fallback = path.join(scenarios_dir, 'configs', f'{scenario_id}.json')
                            if path.exists(fallback):
                                output_file = fallback
                        if path.exists(output_file):
                            yield f"INFO: Replaying generated scenario to HEC: {output_file}\n"
                            sender_path = os.path.join(scenarios_dir, 'scenario_hec_sender.py')
                            send_proc = subprocess.Popen(
                                ['python', sender_path, '--scenario', output_file, '--auto', '--preserve-timestamps'] +
                                ([] if tag_phase else ['--no-phase-tag']) +
                                ([] if not trace_id else ['--trace-id', trace_id]),
                                cwd=scenarios_dir,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                text=True,
                                env=env
                            )
                            for sline in iter(send_proc.stdout.readline, ''):
                                if not sline:
                                    break
                                if should_output_line(sline):
                                    yield sline
                            send_proc.wait()
                            if send_proc.returncode == 0:
                                yield "INFO: Scenario replay to HEC complete\n"
                                
                                # Generate and send background noise if requested
                                if generate_noise and scenario_id == 'finance_mfa_fatigue_scenario':
                                    yield "\n" + "="*80 + "\n"
                                    yield "INFO: Generating background noise data...\n"
                                    yield f"INFO: Creating {noise_events_count} distributed events across 8 days\n"
                                    yield f"INFO: Distribution: 70% business hours (8 AM - 5 PM EST), 30% off-hours\n"
                                    yield "="*80 + "\n"
                                    
                                    try:
                                        noise_gen_path = os.path.join(scenarios_dir, 'finance_mfa_noise_generator.py')
                                        noise_proc = subprocess.Popen(
                                            ['python', noise_gen_path, '--events', str(noise_events_count), '--days', '8'],
                                            cwd=scenarios_dir,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT,
                                            text=True,
                                            env=env
                                        )
                                        for nline in iter(noise_proc.stdout.readline, ''):
                                            if not nline:
                                                break
                                            if should_output_line(nline):
                                                yield nline
                                        noise_proc.wait()
                                        
                                        if noise_proc.returncode == 0:
                                            # Check if streaming mode was used (large volume)
                                            if noise_events_count > 10000:
                                                yield "\nINFO: Streaming mode - noise events sent directly to HEC\n"
                                            else:
                                                # Send noise to HEC via sender script for small volumes
                                                noise_file = path.join(output_dir, 'finance_mfa_noise.json')
                                                if not path.exists(noise_file):
                                                    noise_file = path.join(scenarios_dir, 'configs', 'finance_mfa_noise.json')
                                                
                                                if path.exists(noise_file):
                                                    yield f"\nINFO: Sending background noise to HEC: {noise_file}\n"
                                                    noise_send_proc = subprocess.Popen(
                                                        ['python', sender_path, '--scenario', noise_file, '--auto', '--preserve-timestamps'] +
                                                        ([] if tag_phase else ['--no-phase-tag']) +
                                                        ([] if not trace_id else ['--trace-id', trace_id]),
                                                        cwd=scenarios_dir,
                                                        stdout=subprocess.PIPE,
                                                        stderr=subprocess.STDOUT,
                                                        text=True,
                                                        env=env
                                                    )
                                                    for nsline in iter(noise_send_proc.stdout.readline, ''):
                                                        if not nsline:
                                                            break
                                                        if should_output_line(nsline):
                                                            yield nsline
                                                    noise_send_proc.wait()
                                                    if noise_send_proc.returncode == 0:
                                                        yield "\nINFO: Background noise sent to HEC successfully\n"
                                                    else:
                                                        yield f"\nERROR: Noise replay exited with code {noise_send_proc.returncode}\n"
                                                else:
                                                    yield "\nWARN: Generated noise file not found; skipping HEC replay\n"
                                        else:
                                            yield f"\nERROR: Noise generation exited with code {noise_proc.returncode}\n"
                                    except Exception as ne:
                                        yield f"\nERROR: Failed to generate/send background noise: {ne}\n"
                            else:
                                yield f"ERROR: Scenario replay exited with code {send_proc.returncode}\n"
                        else:
                            yield "WARN: Generated scenario file not found; skipping HEC replay\n"
                except Exception as e:
                    yield f"ERROR: Failed to replay scenario to HEC: {e}\n"
            else:
                yield f"ERROR: Scenario exited with code {rc}\n"
        except Exception as e:
            yield f"ERROR: Scenario execution failed: {e}\n"
    
    return Response(stream_with_context(generate_and_stream()), mimetype='text/plain')

@app.route('/uploads', methods=['POST'])
def upload_file():
    """Upload a CSV, JSON, TXT, LOG, or GZ file"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Validate file extension
    allowed_extensions = {'.csv', '.json', '.txt', '.log', '.gz'}
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in allowed_extensions:
        return jsonify({'error': f'Invalid file type. Allowed: CSV, JSON, TXT, LOG, GZ'}), 400
    
    try:
        # Forward to backend API
        files = {'file': (file.filename, file.stream, file.content_type)}
        resp = requests.post(
            f"{API_BASE_URL}/api/v1/uploads/upload",
            files=files,
            headers=_get_api_headers(),
            timeout=300  # 5 min timeout for large files
        )
        
        if resp.status_code == 201:
            return jsonify(resp.json()), 201
        else:
            error_detail = resp.json().get('detail', resp.text) if resp.headers.get('content-type') == 'application/json' else resp.text
            return jsonify({'error': error_detail}), resp.status_code
    except Exception as e:
        logger.error(f"Failed to upload file: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/uploads', methods=['GET'])
def list_uploads():
    """List uploaded files"""
    try:
        resp = requests.get(
            f"{API_BASE_URL}/api/v1/uploads/uploads",
            headers=_get_api_headers(),
            timeout=10
        )
        if resp.status_code == 200:
            return jsonify({'uploads': resp.json()})
        else:
            return jsonify({'error': f'Backend error: {resp.status_code}'}), resp.status_code
    except Exception as e:
        logger.error(f"Failed to list uploads: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/uploads/<upload_id>', methods=['DELETE'])
def delete_upload(upload_id: str):
    """Delete an uploaded file"""
    try:
        resp = requests.delete(
            f"{API_BASE_URL}/api/v1/uploads/uploads/{upload_id}",
            headers=_get_api_headers(),
            timeout=10
        )
        if resp.status_code == 204:
            return ('', 204)
        else:
            error_detail = resp.json().get('detail', resp.text) if resp.headers.get('content-type') == 'application/json' else resp.text
            return jsonify({'error': error_detail}), resp.status_code
    except Exception as e:
        logger.error(f"Failed to delete upload: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/uploads/process', methods=['POST'])
def process_upload():
    """Process an uploaded file through HEC"""
    data = request.json
    upload_id = data.get('upload_id')
    destination_id = data.get('destination_id')
    batch_size = int(data.get('batch_size', 100))
    eps = float(data.get('eps', 10.0))
    sourcetype = data.get('sourcetype', '').strip()
    endpoint = data.get('endpoint', 'event')  # 'event' or 'raw'
    local_token = data.get('hec_token')  # Token from browser localStorage
    sync_parsers = data.get('sync_parsers', True)  # Enable parser sync by default
    trace_id = (data.get('trace_id') or '').strip()  # Trace ID for event correlation
    
    if not upload_id:
        return jsonify({'error': 'upload_id is required'}), 400
    if not destination_id:
        return jsonify({'error': 'destination_id is required'}), 400
    if not sourcetype:
        return jsonify({'error': 'sourcetype is required'}), 400
    
    def generate_and_stream():
        try:
            # Get upload metadata from backend
            upload_resp = requests.get(
                f"{API_BASE_URL}/api/v1/uploads/uploads/{upload_id}",
                headers=_get_api_headers(),
                timeout=10
            )
            if upload_resp.status_code != 200:
                yield "ERROR: Upload not found\n"
                return
            
            upload_info = upload_resp.json()
            file_type = upload_info.get('file_type')
            line_count = upload_info.get('line_count', 0)
            
            # Get destination info
            dest_resp = requests.get(
                f"{API_BASE_URL}/api/v1/destinations/{destination_id}",
                headers=_get_api_headers(),
                timeout=10
            )
            if dest_resp.status_code != 200:
                yield "ERROR: Destination not found\n"
                return
            
            destination = dest_resp.json()
            if destination.get('type') != 'hec':
                yield "ERROR: Only HEC destinations are supported for file uploads\n"
                return
            
            hec_url = destination.get('url')
            
            # Use local token if provided, otherwise fetch from backend
            if local_token:
                hec_token = local_token
                logger.info(f"Using local token from browser for destination: {destination_id}")
            else:
                # Get decrypted token from backend as fallback
                token_resp = requests.get(
                    f"{API_BASE_URL}/api/v1/destinations/{destination_id}/token",
                    headers=_get_api_headers(),
                    timeout=10
                )
                if token_resp.status_code != 200:
                    yield "ERROR: Failed to retrieve HEC token. Please set a local token in Settings.\n"
                    return
                
                hec_token = token_resp.json().get('token')
                logger.info(f"Using backend token for destination: {destination_id}")
            
            # Fetch config token and URL for parser sync if available
            config_api_url = destination.get('config_api_url')
            config_write_token = None
            github_repo_urls = []
            github_token = None
            if sync_parsers and destination.get('has_config_write_token') and config_api_url:
                try:
                    config_resp = requests.get(
                        f"{API_BASE_URL}/api/v1/destinations/{destination_id}/config-tokens",
                        headers=_get_api_headers(),
                        timeout=10
                    )
                    if config_resp.status_code == 200:
                        config_tokens = config_resp.json()
                        config_write_token = config_tokens.get('config_write_token')
                        logger.info(f"Retrieved config token for parser sync (API URL: {config_api_url})")
                except Exception as ce:
                    logger.warning(f"Failed to retrieve config token: {ce}")
                
                # Fetch GitHub parser repositories from settings
                try:
                    repos_resp = requests.get(
                        f"{API_BASE_URL}/api/v1/settings/parser-repositories",
                        headers=_get_api_headers(),
                        timeout=10
                    )
                    if repos_resp.status_code == 200:
                        repos_data = repos_resp.json()
                        github_repo_urls = [url for url in repos_data.get('repositories', []) if url]
                        github_token = repos_data.get('github_token')
                        if github_repo_urls:
                            logger.info(f"Retrieved {len(github_repo_urls)} GitHub parser repositories")
                except Exception as ge:
                    logger.warning(f"Failed to retrieve GitHub parser repositories: {ge}")
            
            # Parser sync: Check and upload required parser before sending events
            if sync_parsers and config_write_token and config_api_url:
                yield "INFO: Checking required parser in destination SIEM...\n"
                try:
                    # Call the parser sync API for single sourcetype
                    sync_payload = {
                        "sourcetype": sourcetype,
                        "config_api_url": config_api_url,
                        "config_write_token": config_write_token
                    }
                    if github_repo_urls:
                        sync_payload["github_repo_urls"] = github_repo_urls
                    if github_token:
                        sync_payload["github_token"] = github_token
                    
                    sync_resp = requests.post(
                        f"{API_BASE_URL}/api/v1/parser-sync/sync-single",
                        headers=_get_api_headers(),
                        json=sync_payload,
                        timeout=120
                    )
                    if sync_resp.status_code == 200:
                        sync_result = sync_resp.json()
                        status = sync_result.get('status', 'unknown')
                        message = sync_result.get('message', '')
                        if status == 'exists':
                            yield f"INFO: Parser exists: {sourcetype}\n"
                        elif status == 'uploaded':
                            yield f"INFO: Parser uploaded: {sourcetype}\n"
                        elif status == 'failed':
                            yield f"WARN: Parser sync failed: {sourcetype} - {message}\n"
                        elif status == 'no_parser':
                            yield f"WARN: No parser found for: {sourcetype}\n"
                        yield "INFO: Parser sync complete\n"
                    else:
                        yield f"WARN: Parser sync API returned {sync_resp.status_code}, continuing without sync\n"
                except Exception as pe:
                    yield f"WARN: Parser sync failed: {pe}, continuing without sync\n"
            elif sync_parsers:
                yield "INFO: Parser sync skipped (missing config_api_url or config tokens for destination)\n"
            
            yield f"INFO: Processing {file_type.upper()} file with {line_count} records\n"
            yield f"INFO: Sending to {hec_url} at {eps} EPS\n"
            yield f"INFO: Using sourcetype: {sourcetype}\n"
            yield f"INFO: HEC Endpoint: /{endpoint}\n"
            if trace_id:
                yield f"INFO: Trace ID: {trace_id}\n"
            
            # Read the uploaded file from backend data directory
            # Since we're in Flask, we need to read from the backend's upload directory
            backend_upload_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Backend', 'api', 'data', 'uploads'))
            safe_filename = upload_info.get('id') + '_' + upload_info.get('filename')
            file_path = os.path.join(backend_upload_dir, safe_filename)
            
            if not os.path.exists(file_path):
                yield f"ERROR: File not found at {file_path}\n"
                return
            
            # Process file and send to HEC
            import time as time_module
            delay = 1.0 / eps if eps > 0 else 0.1
            sent_count = 0
            
            # Build path to hec_sender.py
            hec_sender_path = os.path.normpath(
                os.path.join(os.path.dirname(__file__), '..', 'Backend', 'event_generators', 'shared', 'hec_sender.py')
            )
            
            # Build HEC URL with endpoint
            base_hec_url = hec_url.rstrip('/')
            if not base_hec_url.endswith('/services/collector'):
                base_hec_url += '/services/collector'
            
            if endpoint == 'event':
                hec_endpoint_url = f"{base_hec_url}/event"
            else:
                hec_endpoint_url = f"{base_hec_url}/raw?sourcetype={sourcetype}"
            
            if file_type == 'json':
                with open(file_path, 'r') as f:
                    data_content = json.load(f)
                    records = data_content if isinstance(data_content, list) else [data_content]
                    
                    for record in records:
                        try:
                            if endpoint == 'event':
                                # Send to HEC /event endpoint with sourcetype in payload
                                headers_local = {
                                    'Authorization': f'Splunk {hec_token}',
                                    'Content-Type': 'application/json'
                                }
                                payload = {
                                    'event': record,
                                    'sourcetype': sourcetype
                                }
                                # Add trace_id as indexed field if provided
                                if trace_id:
                                    payload['fields'] = {'scenario.trace_id': trace_id}
                                resp = requests.post(
                                    hec_endpoint_url,
                                    json=payload,
                                    headers=headers_local,
                                    verify=True,
                                    timeout=10
                                )
                            else:
                                # Send to HEC /raw endpoint (sourcetype in URL)
                                headers_local = {
                                    'Authorization': f'Splunk {hec_token}',
                                    'Content-Type': 'text/plain'
                                }
                                # For raw endpoint, inject trace_id into the record if it's a dict
                                if trace_id and isinstance(record, dict):
                                    record['scenario.trace_id'] = trace_id
                                raw_data = json.dumps(record) if isinstance(record, dict) else str(record)
                                resp = requests.post(
                                    hec_endpoint_url,
                                    data=raw_data,
                                    headers=headers_local,
                                    verify=True,
                                    timeout=10
                                )
                            
                            resp.raise_for_status()
                            sent_count += 1
                            if sent_count % 10 == 0:
                                yield f"INFO: Sent {sent_count}/{len(records)} events\n"
                            time_module.sleep(delay)
                        except Exception as e:
                            yield f"ERROR: Failed to send event: {e}\n"
                            
            elif file_type == 'csv':
                with open(file_path, 'r') as f:
                    reader = csv.DictReader(f)
                    records = list(reader)
                    
                    for record in records:
                        try:
                            if endpoint == 'event':
                                # Send to HEC /event endpoint as JSON with sourcetype
                                headers_local = {
                                    'Authorization': f'Splunk {hec_token}',
                                    'Content-Type': 'application/json'
                                }
                                payload = {
                                    'event': record,
                                    'sourcetype': sourcetype
                                }
                                # Add trace_id as indexed field if provided
                                if trace_id:
                                    payload['fields'] = {'scenario.trace_id': trace_id}
                                resp = requests.post(
                                    hec_endpoint_url,
                                    json=payload,
                                    headers=headers_local,
                                    verify=True,
                                    timeout=10
                                )
                            else:
                                # Send to HEC /raw endpoint (sourcetype in URL)
                                headers_local = {
                                    'Authorization': f'Splunk {hec_token}',
                                    'Content-Type': 'text/plain'
                                }
                                # Add trace_id to record for raw endpoint
                                if trace_id:
                                    record['scenario.trace_id'] = trace_id
                                # Convert CSV row to key=value format for raw endpoint
                                raw_data = ' '.join([f'{k}={v}' for k, v in record.items()])
                                resp = requests.post(
                                    hec_endpoint_url,
                                    data=raw_data,
                                    headers=headers_local,
                                    verify=True,
                                    timeout=10
                                )
                            
                            resp.raise_for_status()
                            sent_count += 1
                            if sent_count % 10 == 0:
                                yield f"INFO: Sent {sent_count}/{len(records)} events\n"
                            time_module.sleep(delay)
                        except Exception as e:
                            yield f"ERROR: Failed to send event: {e}\n"
            
            elif file_type in ['txt', 'log']:
                # Process text/log files line by line
                with open(file_path, 'r') as f:
                    lines = [line.rstrip('\n') for line in f if line.strip()]
                    
                    for line in lines:
                        try:
                            if endpoint == 'event':
                                # Send to HEC /event endpoint (wrap line in JSON)
                                headers_local = {
                                    'Authorization': f'Splunk {hec_token}',
                                    'Content-Type': 'application/json'
                                }
                                payload = {
                                    'event': line,
                                    'sourcetype': sourcetype
                                }
                                # Add trace_id as indexed field if provided
                                if trace_id:
                                    payload['fields'] = {'scenario.trace_id': trace_id}
                                resp = requests.post(
                                    hec_endpoint_url,
                                    json=payload,
                                    headers=headers_local,
                                    verify=True,
                                    timeout=10
                                )
                            else:
                                # Send to HEC /raw endpoint
                                headers_local = {
                                    'Authorization': f'Splunk {hec_token}',
                                    'Content-Type': 'text/plain'
                                }
                                # For raw endpoint, append trace_id to line if provided
                                raw_line = f"{line} scenario.trace_id={trace_id}" if trace_id else line
                                resp = requests.post(
                                    hec_endpoint_url,
                                    data=raw_line,
                                    headers=headers_local,
                                    verify=True,
                                    timeout=10
                                )
                            
                            resp.raise_for_status()
                            sent_count += 1
                            if sent_count % 10 == 0:
                                yield f"INFO: Sent {sent_count}/{len(lines)} events\n"
                            time_module.sleep(delay)
                        except Exception as e:
                            yield f"ERROR: Failed to send event: {e}\n"
            
            else:
                yield f"ERROR: Unsupported file type: {file_type}\n"
                return
            
            yield f"INFO: Successfully sent {sent_count} events to HEC\n"
            
        except Exception as e:
            logger.error(f"Failed to process upload: {e}", exc_info=True)
            yield f"ERROR: Failed to process upload: {e}\n"
    
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
    log_count = int(data.get('count', 3)) if data.get('count') is not None else None
    eps = float(data.get('eps', 1.0))
    continuous = data.get('continuous', False)
    speed_mode = data.get('speed_mode', False)
    syslog_ip = data.get('ip')
    syslog_port = int(data.get('port')) if data.get('port') is not None else None
    syslog_protocol = data.get('protocol')
    product_id = data.get('product')
    local_hec_token = data.get('hec_token')  # Token from browser localStorage
    metadata_fields = data.get('metadata')  # Custom metadata fields as JSON object
    # Unified destination id (preferred)
    unified_dest_id = data.get('destination_id')
    # Back-compat fields
    hec_dest_id = data.get('hec_destination_id')
    syslog_dest_id = data.get('syslog_destination_id')
    
    # Auto-enable speed mode for high EPS
    if continuous and eps > 1000 and not speed_mode:
        speed_mode = True
        logger.info("Auto-enabling Speed Mode for high throughput (>1000 EPS)")
    
    # Set log_count to a large number for continuous mode
    if continuous:
        log_count = 999999999  # Effectively infinite
    
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
                    
                    hec_url = chosen.get('url')
                    dest_id = chosen.get('id')
                    
                    # Use local token if provided, otherwise fetch from backend
                    if local_hec_token:
                        hec_token = local_hec_token
                        logger.info(f"Using local token from browser for destination: {dest_id}")
                    else:
                        # Fetch decrypted token from backend as fallback
                        token_resp = requests.get(
                            f"{API_BASE_URL}/api/v1/destinations/{dest_id}/token",
                            headers=_get_api_headers(),
                            timeout=10
                        )
                        if token_resp.status_code != 200:
                            yield "ERROR: Failed to retrieve HEC token from backend. Please set a local token in Settings.\n"
                            return
                        
                        hec_token = token_resp.json().get('token')
                        logger.info(f"Using backend token for destination: {dest_id}")
                    
                    if not hec_url or not hec_token:
                        yield "ERROR: Selected HEC destination is incomplete or token missing.\n"
                        return
                    
                    logger.info(f"Resolved HEC destination: id={dest_id}, url={hec_url}")
                except Exception as e:
                    logger.error(f"Failed to resolve HEC destination: {e}", exc_info=True)
                    yield f"ERROR: Failed to resolve HEC destination: {e}\n"
                    return

                yield f"INFO: Starting HEC send to {hec_url}...\n"
                if continuous:
                    speed_indicator = " (SPEED MODE)" if speed_mode else ""
                    yield f"INFO: Running in CONTINUOUS mode for product '{product_id}' at {eps} EPS{speed_indicator} (press Stop to end)\n"
                else:
                    yield f"INFO: Sending {log_count} events for product '{product_id}' at {eps} EPS\n"

                # Build path to hec_sender.py (Frontend/../Backend/event_generators/shared/hec_sender.py)
                hec_sender_path = os.path.normpath(
                    os.path.join(os.path.dirname(__file__), '..', 'Backend', 'event_generators', 'shared', 'hec_sender.py')
                )
                if not os.path.exists(hec_sender_path):
                    yield f"ERROR: HEC sender not found at {hec_sender_path}\n"
                    return
                
                yield f"DEBUG: Using HEC sender at {hec_sender_path}\n"
                yield f"DEBUG: Product: {product_id}, Count: {log_count}, EPS: {eps}, Continuous: {continuous}, Speed Mode: {speed_mode}\n"

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
                env['S1_HEC_URL'] = normalized_hec_url
                # Enable TLS compatibility for older/misconfigured servers
                env['S1_HEC_TLS_LOW'] = '1'
                # Enable automatic insecure fallback as last resort
                env['S1_HEC_AUTO_INSECURE'] = 'true'
                
                if continuous:
                    # Batch mode for continuous
                    env['S1_HEC_BATCH'] = '1'
                    # Optimize batch size based on EPS
                    if eps >= 10000:
                        # High EPS: larger batches, faster flush
                        env['S1_HEC_BATCH_MAX_BYTES'] = str(2 * 1024 * 1024)  # 2MB batches for high throughput
                        env['S1_HEC_BATCH_FLUSH_MS'] = '200'  # Flush every 0.2 seconds (5x per second)
                    elif eps >= 1000:
                        # Medium EPS: balanced batches
                        env['S1_HEC_BATCH_MAX_BYTES'] = str(512 * 1024)  # 512KB batches
                        env['S1_HEC_BATCH_FLUSH_MS'] = '300'  # Flush every 0.3 seconds
                    else:
                        # Low EPS: smaller batches for visibility
                        env['S1_HEC_BATCH_MAX_BYTES'] = str(256 * 1024)  # 256KB batches
                        env['S1_HEC_BATCH_FLUSH_MS'] = '500'  # Flush every 0.5 seconds
                else:
                    # Single-send mode for small counts
                    env['S1_HEC_BATCH'] = '0'
                
                # Enable debug output to see batch flushes and responses
                env['S1_HEC_DEBUG'] = '1'
                # Disable Python output buffering
                env['PYTHONUNBUFFERED'] = '1'

                # Calculate delay from EPS: delay = 1 / eps
                delay = 1.0 / eps if eps > 0 else 1.0
                # Use -u flag for unbuffered Python output
                # Use --verbosity info for periodic status updates instead of per-event output
                command = ['python3', '-u', hec_sender_path, '--product', product_id, '-n', str(log_count), 
                           '--min-delay', str(delay), '--max-delay', str(delay), '--verbosity', 'info']
                
                # Add metadata fields if provided
                if metadata_fields:
                    # Metadata should be a dict, convert to JSON string for command line
                    import json as json_module
                    if isinstance(metadata_fields, dict):
                        command.extend(['--metadata', json_module.dumps(metadata_fields)])
                        logger.info(f"Adding metadata fields: {metadata_fields}")
                    else:
                        logger.warning(f"Invalid metadata format (expected dict): {type(metadata_fields)}")
                
                # Add speed mode flag
                if speed_mode:
                    command.append('--speed-mode')
                
                command_str = ' '.join(command)
                logger.info(f"Executing HEC sender: {command_str}")
                yield f"DEBUG: Running command: {command_str}\n"
                yield f"DEBUG: Environment vars: S1_HEC_BATCH={env.get('S1_HEC_BATCH')}, S1_HEC_DEBUG={env.get('S1_HEC_DEBUG')}\n"
                
                try:
                    process = subprocess.Popen(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,  # Merge stderr into stdout for better debugging
                        text=True,
                        bufsize=1,  # Line buffered
                        env=env
                    )
                    yield f"DEBUG: Process started with PID {process.pid}\n"
                except Exception as e:
                    yield f"ERROR: Failed to start process: {e}\n"
                    logger.error(f"Failed to start HEC sender process: {e}", exc_info=True)
                    return

                # Stream sanitized output
                line_count = 0
                event_count = 0
                import select
                
                yield "DEBUG: Starting to read output...\n"
                
                try:
                    # Check if process exits immediately
                    import time
                    time.sleep(0.5)
                    poll_result = process.poll()
                    if poll_result is not None:
                        # Process exited immediately
                        remaining_output = process.stdout.read()
                        yield f"ERROR: Process exited immediately with code {poll_result}\n"
                        if remaining_output:
                            sanitized = remaining_output.replace(hec_token, '***REDACTED***')
                            yield f"Output:\n{sanitized}\n"
                        return
                    
                    yield "DEBUG: Process is running, reading output lines...\n"
                    
                    for line in iter(process.stdout.readline, ''):
                        if not line:
                            # Check if process has exited
                            if process.poll() is not None:
                                yield f"DEBUG: Process exited with code {process.returncode}\n"
                                break
                            continue
                        
                        # Check if client disconnected (for continuous mode)
                        if request.environ.get('werkzeug.socket'):
                            try:
                                # This will fail if client disconnected
                                request.environ.get('werkzeug.socket').getpeername()
                            except:
                                logger.info("Client disconnected, terminating process")
                                process.terminate()
                                yield "INFO: Stopped by client disconnect\n"
                                break
                        
                        line_count += 1
                        # Redact token from output
                        sanitized = line.replace(hec_token, '***REDACTED***')
                        yield sanitized
                        logger.debug(f"HEC sender output line {line_count}: {sanitized.strip()}")
                        
                        # Count successful events for continuous mode progress
                        if continuous:
                            # Count based on status messages (QUEUED for batch, OK for non-batch)
                            if 'queued' in sanitized.lower() or ('status' in sanitized.lower() and 'ok' in sanitized.lower()):
                                event_count += 1
                                if event_count % 100 == 0:
                                    yield f"INFO: {event_count} events queued/sent so far...\n"
                except (GeneratorExit, BrokenPipeError):
                    # Client disconnected
                    logger.info("Client disconnected (broken pipe), terminating process")
                    process.terminate()
                    return

                # Wait for process completion
                process.wait()
                logger.info(f"HEC sender process completed with return code: {process.returncode}")
                
                # -15 is SIGTERM from our terminate() call
                if process.returncode != 0 and process.returncode != -15:
                    logger.error(f"HEC send failed with return code {process.returncode}")
                    yield f"ERROR: HEC send failed with code {process.returncode}\n"
                elif continuous and event_count > 0:
                    yield f"INFO: Stopped after sending {event_count} events\n"
                else:
                    yield f"INFO: Successfully sent {log_count if not continuous else event_count} events to HEC\n"
                    logger.info(f"Successfully sent {log_count if not continuous else event_count} events")

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

