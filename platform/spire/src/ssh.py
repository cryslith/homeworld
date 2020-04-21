import os
import subprocess
import tempfile

import configuration
import util


def build_ssh(node: configuration.Node, *script: str, ssh_options=[]) -> list:
    return [
        'ssh',
        '-F', os.path.join(configuration.get_project(), 'ssh_config'),
        '-o', 'BatchMode=yes',
        '-o', 'ConnectTimeout=1',
        *ssh_options,
        node.external_dns_name(),
        '--',
        *script,
    ]


def build_scp_up(node: configuration.Node, source_path: str, dest_path: str) -> list:
    return [
        'scp',
        '-F', os.path.join(configuration.get_project(), 'ssh_config'),
        '-o', 'BatchMode=yes',
        '-o', 'ConnectTimeout=1',
        '--',
        source_path,
        '{}:{}'.format(node.external_dns_name(), dest_path),
    ]


def check_ssh(node: configuration.Node, *script: str, ssh_options=[]) -> None:
    subprocess.check_call(build_ssh(node, *script, ssh_options=ssh_options))


def check_ssh_output(node: configuration.Node, *script: str, ssh_options=[]) -> bytes:
    return subprocess.check_output(build_ssh(node, *script, ssh_options=ssh_options))


def check_scp_up(node: configuration.Node, source_path: str, dest_path: str) -> None:
    subprocess.check_call(build_scp_up(node, source_path, dest_path))


def upload_bytes(node: configuration.Node, source_bytes: bytes, dest_path: str) -> None:
    # tempfile.TemporaryDirectory() creates the directory with 0o600, which protects the data if it's sensitive
    with tempfile.TemporaryDirectory() as scratchdir:
        scratchpath = os.path.join(scratchdir, "scratch")
        util.writefile(scratchpath, source_bytes)
        check_scp_up(node, scratchpath, dest_path)
        os.remove(scratchpath)
