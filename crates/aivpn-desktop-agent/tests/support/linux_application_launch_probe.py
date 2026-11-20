"""Запуск, наследование и шаблоны через настоящую службу в отдельном guest."""
import hashlib
import ctypes
import json
import os
import re
from pathlib import Path
import socket
import struct
import subprocess
import time

import vertical_probe as v
from linux_multi_profile_probe import cli


def diagnose_policy():
    """Читаем контекст собственного последнего выбора, не меняя карты BPF."""
    v.lab.require_guest()
    library = ctypes.CDLL('libbpf.so.1', use_errno=True)
    library.bpf_obj_get.argtypes = [ctypes.c_char_p]
    library.bpf_map_get_info_by_fd.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    library.bpf_map_lookup_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    cpus = library.libbpf_num_possible_cpus()
    assert 0 < cpus <= 256
    for path in Path('/sys/fs/bpf').rglob('scratch'):
        fd = library.bpf_obj_get(os.fsencode(path))
        assert fd >= 0
        try:
            info = ctypes.create_string_buffer(256)
            length = ctypes.c_uint(256)
            assert library.bpf_map_get_info_by_fd(fd, info, ctypes.byref(length)) == 0
            words = struct.unpack_from('=6I', info.raw)
            assert words[0] == 6 and words[2] == 4 and 8876 <= words[3] <= 16384 and words[4] == 4
            stride = (words[3] + 7) & ~7
            for index in range(4):
                key = ctypes.c_uint(index)
                data = ctypes.create_string_buffer(stride * cpus)
                assert library.bpf_map_lookup_elem(fd, ctypes.byref(key), data) == 0
                for cpu in range(cpus):
                    offset = cpu * stride + 8192
                    origin = struct.unpack_from('=5I', data.raw, offset)
                    count, family = struct.unpack_from('=2I', data.raw, offset + 20)
                    if origin[1] != 1000 or count > 32 or family not in [4, 6]:
                        continue
                    parents = [struct.unpack_from('=5I', data.raw, offset + 44 + i * 20) for i in range(count)]
                    print('POLICY_CONTEXT ' + json.dumps({'slot': index, 'cpu': cpu, 'process': origin,
                          'parent_count': count, 'parents': parents, 'field_order': ['owner_kind', 'owner', 'application', 'package', 'resolved']}), flush=True)
        finally:
            os.close(fd)


def main():
    server, server_log, endpoint, echoes, reader, capture = v.prepare_environment(
        ['python3', '/lab/dns_endpoint.py'])
    service = stream = listener = None
    original = b'nameserver 192.0.2.1\noptions timeout:1 attempts:1\n'
    rows = []
    try:
        home = Path('/home/cli-fixture')
        home.mkdir(mode=0o700, parents=True)
        os.chown(home, 1000, 1000)
        for family in ['-4', '-6']:
            v.lab.command(['ip', family, 'rule', 'del', 'pref', '100', 'fwmark', '0xa1', 'lookup', '200'])
        Path('/etc/resolv.conf').unlink(missing_ok=True)
        Path('/etc/resolv.conf').write_bytes(original)
        Path('/etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: files dns\n')
        Path('/var/lib/aivpn-app-routing').mkdir(mode=0o700)
        runtime = Path('/run/aivpn-app-routing')
        runtime.mkdir(mode=0o755)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(runtime / 'control.sock'))
        os.chmod(runtime / 'control.sock', 0o666)
        listener.listen(32)
        fd = listener.fileno()
        stream = Path('/run/routing-service.log').open('wb')
        launch = "import os,sys; fd=int(sys.argv[1]); os.dup2(fd,3,inheritable=True); os.close(fd) if fd!=3 else None; os.environ.update(LISTEN_PID=str(os.getpid()),LISTEN_FDS='1'); os.execve('/usr/libexec/aivpn/aivpn',['aivpn','__routing-service','--dns-provider','file','--dns-upstream','198.18.0.53:53'],os.environ)"
        service = subprocess.Popen(['/usr/bin/python3', '-c', launch, str(fd)], pass_fds=(fd,), stdout=stream, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 25
        while True:
            assert service.poll() is None, 'Служба завершилась при запуске'
            try:
                cli(['status'])
                break
            except (AssertionError, subprocess.TimeoutExpired):
                if time.monotonic() > deadline:
                    raise
                time.sleep(.1)
        profile = cli(['register', 'application-launch-cli'])['profile']
        cli(['dns', 'set', profile, '--acknowledge-outage'], uid=0)
        script = home / 'выбранный скрипт'
        script.write_text('#!/usr/bin/python3\n' + v.lab.CLIENT)
        script.chmod(0o755)
        os.chown(script, 1000, 1000)
        policy = {'version': 1, 'id': 'application-launch', 'generation': 1, 'platform': 'linux',
                  'owner': {'kind': 'linux_user', 'uid': 1000}, 'default_action': {'route': 'system'},
                  'dns': {'kind': 'shared_vpn', 'profile': profile, 'acknowledge_outage': True}, 'rules': []}

        def rule(ident, image, route, destination=None):
            return {'id': ident, 'application': {'kind': 'executable', 'path': image} if image else {'kind': 'any'},
                    'destination': destination, 'inherit_children': True,
                    'action': {'route': route, **({'profile': profile} if route == 'vpn' else {})}}

        policy['rules'] = [rule('parent', '/usr/bin/binding-a', 'vpn'),
                           rule('explicit-child', '/usr/bin/binding-b', 'system'),
                           rule('script', str(script), 'vpn')]
        policy_file = Path('/run/launch-policy.json')

        def apply(previous=None):
            policy_file.write_text(json.dumps(policy))
            policy_file.chmod(0o644)
            cli(['apply', str(policy_file), *(['--expected-generation', str(previous)] if previous is not None else [])])

        apply()
        connection = Path('/run/launch-connection.json')
        connection.write_bytes(Path('/run/vertical-connection.json').read_bytes())
        connection.chmod(0o600)
        os.chown(connection, 1000, 1000)
        cli(['start', profile, '--connection-file', str(connection)])
        deadline = time.monotonic() + 25
        while True:
            record = next(p for p in cli(['profiles'])['profiles'] if p['id'] == profile)
            if record['ready_ipv4']:
                break
            assert service.poll() is None
            assert time.monotonic() < deadline, 'Профиль не готов'
            time.sleep(.1)

        environment = os.environ | {'HOME': str(home), 'XDG_DATA_HOME': str(home / '.local/share')}

        def user(arguments, success=True):
            # Новый наблюдаемый launcher, как после запуска capture до входа пользователя.
            # Root Python оркестратора существовал до установки hooks и не служит доказанным origin.
            bootstrap = 'import os,sys; os.setgroups([]); os.setgid(1000); os.setuid(1000); os.execv(sys.argv[1],sys.argv[1:])'
            result = subprocess.run(['/usr/bin/python3', '-c', bootstrap, *arguments], env=environment,
                                    capture_output=True, text=True, timeout=15)
            if success:
                assert result.returncode == 0, {'command': arguments[0], 'code': result.returncode, 'error': result.stderr[-1200:]}
            else:
                assert result.returncode != 0, 'Ожидался отказ'
            return result

        def probe(label, image, expected, kind=socket.SOCK_STREAM, target='198.18.0.53',
                  parent=None, desktop=False, script_mode=False):
            source_port = str(61000 + len(rows))
            arguments = [label, target, str(socket.AF_INET), str(kind), source_port]
            code = v.lab.CLIENT.replace('s.settimeout(.5)', 's.settimeout(3)')
            if script_mode:
                command = [image, *arguments]
            elif parent:
                parent_code = 'import subprocess,sys; sys.exit(subprocess.run([sys.argv[1],"-c",sys.argv[2],*sys.argv[3:]]).returncode)'
                command = [parent, '-c', parent_code, image, code, *arguments]
            else:
                command = [image, '-c', code, *arguments]
            if desktop:
                literal = 'пробел %F \\ " $HOME `uname` ; $(false)\nстрока'
                command[2] = 'import sys\nassert sys.argv.pop()==' + repr(literal) + '\n' + code
                command.append(literal)
                installed = user(['/usr/libexec/aivpn/aivpn','app-routing', 'install-desktop', '--name', 'Тест приложения', '--', *command])
                path = Path(json.loads(installed.stdout)['desktop_entry'])
                user(['/usr/bin/desktop-file-validate', str(path)])
                result = user(['/usr/bin/gio', 'launch', str(path)])
                original_entry = path.read_bytes()
                path.write_bytes(original_entry + '# Пользовательская правка\n'.encode())
                changed = hashlib.sha256(path.read_bytes()).hexdigest()
                user(['/usr/libexec/aivpn/aivpn','app-routing', 'install-desktop', '--name', 'Тест приложения', '--', *command], success=False)
                assert hashlib.sha256(path.read_bytes()).hexdigest() == changed, 'Правка ярлыка перезаписана'
            else:
                result = user(['/usr/bin/aivpn-client', 'app', 'run', '--', *command])
            value = json.loads(result.stdout)
            time.sleep(.05)
            seen = [r for r in echoes if r.get('label') == label]
            passed = value['echo'] and bool(seen) and all(r['peer'] == expected for r in seen)
            row = {'case': label, 'pass': passed, 'expected': expected, 'result': value, 'server_echo': seen}
            rows.append(row)
            print('VERTICAL_CASE ' + json.dumps(row), flush=True)
            if not passed:
                print('POLICY_PROFILE_STATE ' + json.dumps(cli(['profiles'])), flush=True)
                diagnose_policy()
            assert passed, row

        for kind in [socket.SOCK_STREAM, socket.SOCK_DGRAM]:
            probe('launch-selected-' + str(kind), '/usr/bin/binding-a', '10.77.0.2', kind)
            probe('launch-system-' + str(kind), '/usr/bin/binding-b', '192.0.2.2', kind)
        probe('launch-inherited', '/usr/bin/binding-unknown', '10.77.0.2', parent='/usr/bin/binding-a')
        probe('launch-explicit-child', '/usr/bin/binding-b', '192.0.2.2', parent='/usr/bin/binding-a')
        probe('launch-script', str(script), '10.77.0.2', script_mode=True)
        probe('launch-desktop-literal-arguments', '/usr/bin/binding-a', '10.77.0.2', desktop=True)
        policy['generation'] = 2
        policy['default_action'] = {'route': 'vpn', 'profile': profile}
        policy['rules'] = [rule('excluded', '/usr/bin/binding-b', 'system')]
        apply(1)
        print('POLICY_PROFILE_STATE ' + json.dumps(cli(['profiles'])), flush=True)
        probe('all-except-selected-vpn', '/usr/bin/binding-unknown', '10.77.0.2')
        probe('all-except-excluded-system', '/usr/bin/binding-b', '192.0.2.2')
        policy['generation'] = 3
        policy['default_action'] = {'route': 'system'}
        policy['rules'] = [rule('app-and-cidr', '/usr/bin/binding-a', 'vpn', '198.18.0.53/32'),
                           rule('network-only', None, 'vpn', '198.18.0.54/32')]
        apply(2)
        probe('combined-app-network', '/usr/bin/binding-a', '10.77.0.2')
        probe('combined-network-only', '/usr/bin/binding-b', '10.77.0.2', target='198.18.0.54')
        probe('combined-unselected-system', '/usr/bin/binding-unknown', '192.0.2.2')
        cli(['stop', profile])
        cli(['remove', '--generation', '3'])
        cli(['dns', 'clear'], uid=0)
        assert Path('/etc/resolv.conf').read_bytes() == original
        service.terminate()
        service.wait(timeout=15)
        assert service.returncode == 0
        print('VERTICAL_SUMMARY ' + json.dumps({'pass': True, 'application_launch': True, 'native_cli': True,
              'ordinary_uid': 1000, 'inheritance': True, 'explicit_child_override': True, 'script': True,
              'desktop_literal_arguments': True, 'manual_desktop_edit_preserved': True, 'both_templates': True,
              'combined_cidr': True, 'rows': len(rows), 'original_dns_restored': True, 'public_active': False}), flush=True)
    finally:
        if service and service.poll() is None:
            service.terminate()
            try:
                service.wait(timeout=10)
            except subprocess.TimeoutExpired:
                service.kill()
                service.wait(timeout=3)
        if stream:
            stream.close()
        log = Path('/run/routing-service.log')
        if log.exists():
            tail = re.sub(r'aivpn://\S+|[A-Za-z0-9+/=_-]{32,}', '[REDACTED]', log.read_text(errors='replace')[-5000:])
            print('SERVICE_LOG_TAIL ' + json.dumps(tail), flush=True)
        if listener:
            listener.close()
        for process in [server, endpoint]:
            process.terminate()
            process.wait(timeout=5)
        server_log.close()
        reader.join(timeout=2)
        capture.close()
        print('VERTICAL_CLEANED', flush=True)


if __name__ == '__main__':
    main()
