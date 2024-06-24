#!/usr/bin/env python3
import sys, os
import inspect
import signal
from getopt import getopt

import socket
import multiprocessing, threading

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

entry_file = os.path.basename(inspect.stack()[-1].filename)

help_text = f'''http-tunnel

Socket over HTTP.
Version: 0.1

Usage:
    {entry_file} -c [-h HOST] [-p PORT] [-r URL] [-d HOST:PORT] [-b BUFFER] [-q QUEUE]
    {entry_file} -s [-h HOST] [-p PORT] [-m NUM] [-b BUFFER] [-q QUEUE]

Options:
    --help                          Show this message.

    -c, --client                    Run as client.
    -s, --server                    Run as server.

    -h, --host HOST                 Listen IP address. [default: any]
    -p, --port PORT                 Listen port. [default: 8080]

    -r, --remote URL                URL of the remote server. [default: http://localhost:8080]
                                    (Only used in client mode)
    -d, --destination HOST:PORT     Destination that server will connect to. [default: localhost:22]
                                    (Only used in client mode)
    -m, --max-sessions NUM          Maximum sessions that server will accept. [default: 10]
                                    (Only used in server mode)

    -b, --buffer BUFFER             Maximum size in bytes (per packet) that is sent to the tunnel. [default: 32768]
                                    (Find the best number for yourself)
    -q, --queue QUEUE               Maximum packets that are sent to the tunnel at once. [default: 10]
                                    (Find the best number for yourself)
'''


def start_client(**kwargs):
    from http_tunnel.client import handle_connection, settings

    if 'remote' in kwargs:
        settings['forward_url'] = kwargs['remote']
    if 'destination' in kwargs:
        settings['forward_srv'] = kwargs['destination']
    if 'buffer' in kwargs:
        settings['buffer_size'] = kwargs['buffer']
    if 'queue' in kwargs:
        settings['queue_size'] = kwargs['queue']
    host = kwargs.get('host', '')
    port = kwargs.get('port', 8080)

    print('[I] Starting client mode.')
    try:
        _sock = socket.create_server(
            (host, port),
            family=socket.AF_INET6,
            backlog=16,
            reuse_port=(sys.platform != 'win32'),
            dualstack_ipv6=True
        )
    except Exception:
        try:
            _sock = socket.create_server(
                (host, port),
                family=socket.AF_INET,
                backlog=16,
                reuse_port=(sys.platform != 'win32')
            )
        except Exception as identifier:
            print('[E] Failed to create socket:', identifier)
            exit(1)
    print('[I] Listening on:', f'{_sock.getsockname()[0]}:{_sock.getsockname()[1]}')
    _sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    _sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
    _sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
    _sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)

    while True:
        conn, addr = _sock.accept()
        print('[I] Connection accepted:', addr)
        _child = multiprocessing.Process(target=handle_connection, args=(conn, addr, settings))
        _child.start()
        threading.Thread(target=lambda ps: ps.join(), args=(_child,)).start()


def start_server(**kwargs):
    from http_tunnel.server import handle_connection, settings

    if 'max' in kwargs:
        settings['max_sessions'] = kwargs['max']
    if 'buffer' in kwargs:
        settings['buffer_size'] = kwargs['buffer']
    if 'queue' in kwargs:
        settings['queue_size'] = kwargs['queue']
    host = kwargs.get('host', '')
    port = kwargs.get('port', 8080)

    print('[I] Starting server mode.')
    print('[I] Listening on:', f'{host if host else "<any>"}:{port}')
    handle_connection(host, port)


def main():
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    try:
        signal.signal(signal.SIGTSTP, signal.SIG_IGN)
    except Exception:
        pass

    try:
        (opts, args) = getopt(
            sys.argv[1:],
            'csh:p:r:d:m:b:q:',
            [
                'help',
                'client',
                'server',
                'host=',
                'port=',
                'remote=',
                'destination=',
                'max-sessions=',
                'buffer=',
                'queue='
            ]
        )
    except Exception as identifier:
        print('[E] Invalid arguments:', identifier, end='\n\n')
        print(help_text)
        exit(1)
    if len(opts) == 0:
        print('[E] Arguments required.', end='\n\n')
        print(help_text)
        exit(1)
    if len(args) > 0:
        print('[E] Invalid arguments:', args[0], end='\n\n')
        print(help_text)
        exit(1)

    _action = ''
    _args = {}

    for opt in opts:
        if opt[0] in ('-c', '--client'):
            if not _action:
                _action = 'client'
        elif opt[0] in ('-s', '--server'):
            if not _action:
                _action = 'server'
        elif opt[0] in ('-h', '--host'):
            _args['host'] = opt[1]
        elif opt[0] in ('-p', '--port'):
            _args['port'] = int(opt[1])
        elif opt[0] in ('-r', '--remote'):
            _args['remote'] = opt[1]
        elif opt[0] in ('-d', '--destination'):
            _args['destination'] = opt[1]
        elif opt[0] in ('-m', '--max-sessions'):
            _args['max'] = int(opt[1])
        elif opt[0] in ('-b', '--buffer'):
            _args['buffer'] = int(opt[1])
        elif opt[0] in ('-q', '--queue'):
            _args['queue'] = int(opt[1])
        elif opt[0] == '--help':
            print(help_text)
            exit(0)

    if not _action:
        print('[E] Invalid arguments: running mode required.', end='\n\n')
        print(help_text)
        exit(1)

    if _action == 'client':
        start_client(**_args)
    elif _action == 'server':
        start_server(**_args)


if __name__ == '__main__':
    main()
