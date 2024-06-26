#!/usr/bin/env python3
import sys, os
import signal
from getopt import getopt

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

exec_file = os.path.basename(sys.argv[0])

help_text = f'''http-tunnel

Socket over HTTP.
Version: 0.1

Usage:
    {exec_file} -c [-h HOST] [-p PORT] [-r URL] [-d HOST:PORT] [-b BUFFER] [-q QUEUE]
    {exec_file} -s [-h HOST] [-p PORT] [-m NUM] [-b BUFFER] [-q QUEUE]

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
    from http_tunnel.client import client

    host = kwargs.get('host', '')
    port = kwargs.get('port', 8080)
    remote = kwargs.get('remote', None)
    destination = kwargs.get('destination', None)
    buffer = kwargs.get('buffer', None)
    queue = kwargs.get('queue', None)

    client(host, port, remote, destination, buffer, queue)


def start_server(**kwargs):
    from http_tunnel.server import server

    host = kwargs.get('host', '')
    port = kwargs.get('port', 8080)
    max_sessions = kwargs.get('max', None)
    buffer = kwargs.get('buffer', None)
    queue = kwargs.get('queue', None)

    server(host, port, max_sessions, buffer, queue)


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
