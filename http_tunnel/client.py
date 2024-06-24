import socket, threading

import http.client, http.cookies
from requests import Session
import queue

import os, time
from .crypto import Crypto_AES, Crypto_RSA

settings = {
    'forward_url': 'http://localhost:8080',
    'forward_srv': 'localhost:22',
    'buffer_size': 32768,
    'queue_size': 10
}


def handle_connection(conn: socket.socket, addr, settings=settings):
    def close():
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        conn.close()
        print('[I] Connection closed:', addr)

    _req = Session()
    try:
        _res = _req.get(
            f'{settings['forward_url']}/',
            headers={
                'cache-control': 'no-cache',
                'pragma': 'no-cache',
                'connection': 'keep-alive',
                'proxy-connection': 'keep-alive'
            }
        )
    except Exception as identifier:
        print('[E] Request / failed:', identifier)
        close()
        return
    if _res.status_code >= 400:
        print('[E] Response / invalid:', _res.status_code, _res.text)
        close()
        return

    _pem = _res.text
    _rsa = Crypto_RSA()
    try:
        _rsa.load_public_key(_pem)
    except Exception as identifier:
        print('[E] Invalid public key:', identifier)
        print(_pem)
        close()
        return

    _cookie = http.cookies.SimpleCookie()
    # with OAEP padding: maxLen(190)=keyLen(2048)/8-2*hashLen(256)/8-2
    _pass = os.urandom(190)
    _cookie['secret'] = _rsa.encrypt(_pass)
    _aes = Crypto_AES(_pass)
    _cookie['token'] = _aes.encrypt(settings['forward_srv'].encode())
    try:
        _res = _req.get(
            f'{settings['forward_url']}/api/login',
            headers={
                'cookie': _cookie.output(header='', sep=';').strip(),
                'cache-control': 'no-cache',
                'pragma': 'no-cache',
                'connection': 'keep-alive',
                'proxy-connection': 'keep-alive'
            }
        )
    except Exception as identifier:
        print('[E] Request /api/login failed:', identifier)
        close()
        return
    if _res.status_code >= 400:
        print('[E] Response /api/login invalid:', _res.status_code, _res.text)
        close()
        return
    _sid = _res.cookies.get('sid')
    if _sid is None:
        print('[E] Invalid sid in response /api/login.')
        close()
        return
    print('[I] Session started:', _sid)
    _cookie['sid'] = _sid

    _cookie.pop('secret')
    _cookie.pop('token')

    _export_queue = queue.Queue(settings['queue_size'])
    _import_queue = queue.Queue()

    _input_thread = threading.Thread(target=handle_input, args=(conn, _import_queue, _export_queue))
    _input_thread.start()
    _output_thread = threading.Thread(target=handle_output, args=(conn, _import_queue))
    _output_thread.start()

    _done = threading.Event()

    _transfer_thread1 = threading.Thread(
        target=handle_transfer,
        args=(_export_queue, _import_queue, _req, _sid, _aes, 'put', _done)
    )
    _transfer_thread1.start()
    _transfer_thread2 = threading.Thread(
        target=handle_transfer,
        args=(_export_queue, _import_queue, _req, _sid, _aes, 'get', _done)
    )
    _transfer_thread2.start()

    _input_thread.join()
    _output_thread.join()
    _transfer_thread1.join()
    _transfer_thread2.join()

    close()
    try:
        _cookie['nonce'] = _aes.encrypt(str(time.time()).encode())
        _req.get(
            f'{settings['forward_url']}/api/logout',
            headers={
                'cookie': _cookie.output(header='', sep=';').strip(),
                'cache-control': 'no-cache',
                'pragma': 'no-cache',
                'connection': 'close',
                'proxy-connection': 'close'
            }
        )
        _req.close()
        print('[I] Session ended:', _sid)
    except Exception:
        return


def handle_input(conn: socket.socket, iqueue: queue.Queue, equeue: queue.Queue):
    while True:
        try:
            _d = conn.recv(settings['buffer_size'])
        except Exception:
            iqueue.put(None)
            break
        # print('[D] Input:', _d)
        equeue.put(_d)
        if len(_d) == 0:
            break
    equeue.put(None)
    print('[D] Input closed.')


def handle_output(conn: socket.socket, iqueue: queue.Queue):
    _res_tokenid = 0

    while True:
        _item = iqueue.get()
        if _item is not None:
            if _item[0] != _res_tokenid + 1:
                print('[W] Response tokenid mismatch:', _item[0], 'expected:', _res_tokenid + 1)
                iqueue.put(_item)
                continue
            else:
                _res_tokenid = _item[0]
                try:
                    # print('[D] Output:', _item)
                    conn.sendall(_item[1])
                except Exception:
                    break
                if len(_item[1]) == 0:
                    break
        else:
            break
    try:
        conn.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    print('[D] Output closed.')


def _transfer(
    iqueue: queue.Queue,
    req: Session,
    headers: dict,
    aes: Crypto_AES,
    done: threading.Event
):
    try:
        _res = req.get(
            f'{settings['forward_url']}/api/session',
            headers=headers
        )
    except Exception as identifier:
        print('[E] Request /api/session failed:', identifier.args)
        done.set()
        iqueue.put(None)
        return
    if _res.status_code >= 400:
        print('[E] Response /api/session invalid:', _res.status_code, _res.text)
        done.set()
        iqueue.put(None)
        return
    if _res.cookies.get('sid') != req.cookies.get('sid'):
        print('[E] Invalid sid in response /api/session.')
        done.set()
        iqueue.put(None)
        return

    # _res_tokenid = _res.cookies.get('tokenid')
    # _res_token = _res.cookies.get('token')
    _res_tokenid = _res.json().get('tokenid', None)
    _res_token = _res.json().get('token', None)
    if _res_tokenid is None or _res_token is None:
        return
    try:
        _res_tokenid = aes.decrypt(_res_tokenid)
    except Exception as identifier:
        print('[E] Invalid tokenid in response /api/session:', identifier)
        done.set()
        iqueue.put(None)
        return
    _token = zip(_res_tokenid.decode().split(' '), _res_token.split(' '))
    for _id, _encrypted in _token:
        try:
            _d = aes.decrypt(_encrypted)
        except Exception as identifier:
            print('[E] Failed to decrypt token from response /api/session:', identifier)
            done.set()
            iqueue.put(None)
            break
        iqueue.put((int(_id), _d))
        if len(_d) == 0:
            done.set()
            break


def handle_transfer(
    equeue: queue.Queue,
    iqueue: queue.Queue,
    request: Session,
    sid: str,
    aes: Crypto_AES,
    mode: str,
    done: threading.Event
):
    _cookie = http.cookies.SimpleCookie()
    _cookie['sid'] = sid
    _tokenid = 0
    while not done.is_set():
        _cookie['nonce'] = aes.encrypt(str(time.time()).encode())
        if mode == 'get':
            _transfer(
                iqueue,
                request,
                {
                    'cookie': _cookie.output(header='', sep=';').strip(),
                    'cache-control': 'no-cache',
                    'pragma': 'no-cache',
                    'connection': 'keep-alive',
                    'proxy-connection': 'keep-alive'
                },
                aes,
                done
            )
        else:
            _token = [equeue.get()]
            _id = []
            while not equeue.empty():
                try:
                    _token.append(equeue.get_nowait())
                except Exception:
                    break
                if len(_token) >= settings['queue_size']:
                    break

            for _item in _token:
                if _item is None:
                    done.set()
                    break
                _tokenid += 1
                _id.append(str(_tokenid))

            if len(_id) == 0:
                continue

            for _index in range(len(_id)):
                _token[_index] = aes.encrypt(_token[_index])

            # print('[D] sending tokenid:', sid, _id)
            _cookie['tokenid'] = aes.encrypt(' '.join(_id).encode())
            _cookie['token'] = ' '.join(_token[:len(_id)])
            _transfer(
                iqueue,
                request,
                {
                    'cookie': _cookie.output(header='', sep=';').strip(),
                    'cache-control': 'no-cache',
                    'pragma': 'no-cache',
                    'connection': 'keep-alive',
                    'proxy-connection': 'keep-alive'
                },
                aes,
                done
            )
    equeue.put(None)
    print('[D] Transfer closed, mode:', mode)
