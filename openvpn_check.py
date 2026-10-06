#!/usr/bin/env python3
"""Run real OpenVPN checks for the configs selected by the fetcher."""
import base64, json, os, shutil, subprocess, tempfile, time
from pathlib import Path

PUBLIC = Path(os.environ.get('PUBLIC_DIR', Path(__file__).parent / 'public'))
TIMEOUT = int(os.environ.get('OPENVPN_TIMEOUT', '35'))

def run_one(node, work):
    cfg = base64.b64decode(node['config_b64']).decode('utf-8', 'replace')
    cfg_path = work / 'node.ovpn'
    auth_path = work / 'auth.txt'
    cfg_path.write_text(cfg, encoding='utf-8')
    auth_path.write_text('vpn\nvpn\n', encoding='utf-8')
    proc = subprocess.Popen([
        'sudo', 'openvpn', '--config', str(cfg_path), '--auth-user-pass', str(auth_path),
        '--dev', 'tun0', '--route-nopull', '--script-security', '2', '--verb', '3'
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        deadline = time.time() + TIMEOUT
        connected = False
        while time.time() < deadline:
            line = proc.stdout.readline()
            if 'Initialization Sequence Completed' in line:
                connected = True
                break
            if proc.poll() is not None:
                break
        if not connected:
            return False, 'openvpn handshake failed'
        check = subprocess.run(['curl', '--interface', 'tun0', '--connect-timeout', '10', '-fsS', 'https://api.ipify.org'], capture_output=True, text=True, timeout=15)
        if check.returncode != 0 or not check.stdout.strip():
            return False, 'tun0 has no external connectivity'
        node['openvpn_exit_ip'] = check.stdout.strip()
        return True, None
    except Exception as exc:
        return False, str(exc)
    finally:
        proc.terminate()
        try: proc.wait(timeout=5)
        except subprocess.TimeoutExpired: proc.kill()

def main():
    data_path = PUBLIC / 'data.json'
    data = json.loads(data_path.read_text(encoding='utf-8'))
    candidates = [n for n in data.get('available', []) if n.get('config_b64')]
    passed = []
    failed = []
    for i, node in enumerate(candidates, 1):
        with tempfile.TemporaryDirectory(prefix='ovpn-check-') as td:
            ok, error = run_one(node, Path(td))
        if ok: passed.append(node)
        else: failed.append({'host': node.get('host'), 'error': error})
        print(f'OPENVPN {i}/{len(candidates)} {node.get("host")}: {"PASS" if ok else "FAIL"}', flush=True)
    data['available'] = passed
    data.setdefault('stats', {})['openvpn_checked'] = len(candidates)
    data['stats']['openvpn_success'] = len(passed)
    data['stats']['openvpn_failed'] = len(failed)
    data['stats']['success'] = len(passed)
    data_path.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding='utf-8')
    rows = [['HostName','IP','','','Speed','','CountryShort','','','','','','','','OpenVPN_ConfigData_Base64']]
    for n in passed:
        rows.append([n.get('host',''), n.get('ip',''), '', '', n.get('speed','0'), '', n.get('country_code',''), '', '', '', '', '', '', '', n['config_b64']])
    import csv
    with (PUBLIC / 'vpngate-filtered.csv').open('w', encoding='utf-8', newline='') as f:
        csv.writer(f, lineterminator='\n').writerows(rows)
    if not passed:
        raise SystemExit('No OpenVPN node passed real handshake + tun0 egress checks')

if __name__ == '__main__': main()
