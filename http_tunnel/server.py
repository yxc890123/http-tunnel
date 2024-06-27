from typing import Union
from fastapi import FastAPI, Cookie
from fastapi.responses import PlainTextResponse, JSONResponse
import uvicorn

from .crypto import Crypto_AES, Crypto_RSA
from .common import Config, find_packet

import uuid
import queue, socket
import threading

settings = Config()

app = FastAPI(
    title='HTTP Server',
    openapi_url=None,
    docs_url=None,
    redoc_url=None
)
sessions = {}
rsa = Crypto_RSA()


@app.get('/')
def root():
    return PlainTextResponse(rsa.public_pem, headers={'connection': 'close'})


@app.get('/api/login')
def login(
    secret: Union[str, None] = Cookie(default=None),
    token: Union[str, None] = Cookie(default=None)
):
    if not secret or not token:
        return JSONResponse(
            {'error': 'No secret or token found'},
            status_code=400,
            headers={'connection': 'close'}
        )

    try:
        _pass = rsa.decrypt(secret)
    except Exception as identifier:
        print('[E] Failed to decrypt secret:', identifier)
        return JSONResponse(
            {'error': 'Invalid secret'},
            status_code=400,
            headers={'connection': 'close'}
        )

    _aes = Crypto_AES(_pass)
    try:
        _token = _aes.decrypt(token)
    except Exception as identifier:
        print('[E] Failed to decrypt token:', identifier)
        return JSONResponse(
            {'error': 'Invalid token'},
            status_code=400,
            headers={'connection': 'close'}
        )

    try:
        _token = _token.decode().split(':')
        _host = _token[0]
        _port = int(_token[1])
    except Exception as identifier:
        print('[D] Invalid host/port in token:', identifier)
        return JSONResponse(
            {'error': 'Invalid token'},
            status_code=400,
            headers={'connection': 'close'}
        )

    for _s in list(sessions.keys()):
        _session: Forwarder = sessions[_s]
        _t: threading.Thread = _session.output_thread
        if not _t.is_alive():
            _session.close()
            sessions.pop(_s, None)

    if len(sessions) >= settings.max_sessions:
        return JSONResponse(
            {'error': 'Too many sessions'},
            status_code=429,
            headers={'connection': 'close'}
        )

    _id = str(uuid.uuid4())
    while _id in sessions:
        _id = str(uuid.uuid4())

    _session = Forwarder(_host, _port)
    _session.open()
    if _session.sock:
        print('[I] Session opened:', _id, _host, _port)
        _session.cipher = _aes
        _session.input_thread = threading.Thread(target=_session.handle_input)
        _session.input_thread.start()
        _session.output_thread = threading.Thread(target=_session.handle_output)
        _session.output_thread.start()
        sessions[_id] = _session
        _res = JSONResponse(
            {'error': None},
            headers={'connection': 'keep-alive'}
        )
        _res.set_cookie(key='sid', value=_id, path='/api/')
        return _res
    else:
        return JSONResponse(
            {'error': 'Failed to connect to server'},
            status_code=503,
            headers={'connection': 'close'}
        )


@app.get('/api/session')
def session(
    sid: Union[str, None] = Cookie(default=None),
    tokenid: Union[str, None] = Cookie(default=None),
    token: Union[str, None] = Cookie(default=None),
    nonce: Union[str, None] = Cookie(default=None)
):
    if not sid:
        return JSONResponse(
            {'error': 'No session ID found'},
            status_code=400,
            headers={'connection': 'close'}
        )
    if type(tokenid) is not type(token):
        return JSONResponse(
            {'error': 'Invalid token'},
            status_code=400,
            headers={'connection': 'close'}
        )
    if sid not in sessions:
        return JSONResponse(
            {'error': 'Session ID not found'},
            status_code=404,
            headers={'connection': 'close'}
        )

    _session: Forwarder = sessions[sid]
    try:
        _nonce = float(_session.cipher.decrypt(nonce))
    except Exception as identifier:
        print('[E] Failed to decrypt nonce:', identifier)
        return JSONResponse(
            {'error': 'Invalid nonce'},
            status_code=400,
            headers={'connection': 'close'}
        )

    _timeout = 10.0
    if tokenid is not None:
        if _nonce <= _session.put_nonce:
            print('[E] Received duplicated nonce.')
            return JSONResponse(
                {'error': 'Duplicated nonce'},
                status_code=403,
                headers={'connection': 'close'}
            )
        else:
            _session.put_nonce = _nonce

        try:
            tokenid = _session.cipher.decrypt(tokenid)
        except Exception as identifier:
            print('[E] Failed to decrypt tokenid:', identifier)
            return JSONResponse(
                {'error': 'Invalid tokenid'},
                status_code=400,
                headers={'connection': 'close'}
            )

        # print('[D] received tokenid:', tokenid)
        _timeout = 0.02

        for _id, _encrypted in zip(tokenid.decode().split(' '), token.split(' ')):
            try:
                _t = _session.cipher.decrypt(_encrypted)
            except Exception as identifier:
                print('[E] Failed to decrypt token:', identifier)
                return JSONResponse(
                    {'error': 'Invalid token'},
                    status_code=400,
                    headers={'connection': 'close'}
                )
            _session.iqueue.put((int(_id), _t))
            if not _session.sock:
                return JSONResponse(
                    {'error': 'Session closed'},
                    status_code=409,
                    headers={'connection': 'close'}
                )
            if len(_t) == 0:
                _session.close()
                sessions.pop(sid, None)
                break
    else:
        if _nonce <= _session.get_nonce:
            print('[E] Received duplicated nonce.')
            return JSONResponse(
                {'error': 'Duplicated nonce'},
                status_code=403,
                headers={'connection': 'close'}
            )
        else:
            _session.get_nonce = _nonce

    try:
        _outq_item = _session.oqueue.get(timeout=_timeout)
    except Exception:
        if not _session.sock:
            return JSONResponse(
                {'error': 'Session closed'},
                status_code=409,
                headers={'connection': 'close'}
            )
        _res = JSONResponse(
            {'error': None},
            status_code=202,
            headers={'connection': 'keep-alive'}
        )
        _res.set_cookie(key='sid', value=sid, path='/api/')
        return _res

    _session.res_tokenid += 1
    _res_tokenid = [str(_session.res_tokenid)]
    _res_token = [_session.cipher.encrypt(_outq_item)]
    while not _session.oqueue.empty():
        try:
            _outq_item = _session.oqueue.get_nowait()
        except Exception:
            break
        _session.res_tokenid += 1
        _res_tokenid.append(str(_session.res_tokenid))
        _res_token.append(_session.cipher.encrypt(_outq_item))
        if len(_res_tokenid) >= settings.queue_size:
            break

    # print('[D] sending tokenid:', sid, _res_tokenid)
    _res = JSONResponse(
        {
            'error': None,
            'tokenid': _session.cipher.encrypt(' '.join(_res_tokenid).encode()),
            'token': ' '.join(_res_token)
        },
        headers={'connection': 'keep-alive'}
    )
    _res.set_cookie(key='sid', value=sid, path='/api/')
    # _res.set_cookie(key='tokenid', value=_session.cipher.encrypt(' '.join(_res_tokenid)), path='/api/')
    # _res.set_cookie(key='token', value=' '.join(_res_token), path='/api/')
    return _res


@app.get('/api/logout')
def logout(
    sid: Union[str, None] = Cookie(default=None),
    nonce: Union[str, None] = Cookie(default=None)
):
    print('[I] Closing session:', sid)
    if not sid:
        return JSONResponse(
            {'error': 'No session ID found'},
            status_code=400,
            headers={'connection': 'close'}
        )
    if sid not in sessions:
        return JSONResponse(
            {'error': 'Session ID not found'},
            status_code=404,
            headers={'connection': 'close'}
        )

    _session: Forwarder = sessions[sid]
    try:
        _nonce = float(_session.cipher.decrypt(nonce))
    except Exception as identifier:
        print('[E] Failed to decrypt nonce:', identifier)
        return JSONResponse(
            {'error': 'Invalid nonce'},
            status_code=400,
            headers={'connection': 'close'}
        )
    if _nonce <= _session.put_nonce or _nonce <= _session.get_nonce:
        print('[E] Received duplicated nonce.')
        return JSONResponse(
            {'error': 'Duplicated nonce'},
            status_code=403,
            headers={'connection': 'close'}
        )

    _session.close()
    sessions.pop(sid, None)
    return JSONResponse({'error': None}, headers={'connection': 'close'})


class Forwarder(object):
    def __init__(self, host: str, port: int) -> None:
        self.cipher = None
        self.get_nonce = 0.0
        self.put_nonce = 0.0
        self.host = host
        self.port = port
        self.sock = None
        self.tokenid = 0
        self.res_tokenid = 0
        self.input_thread = None
        self.output_thread = None
        self.iqueue = queue.Queue()
        self.oqueue = queue.Queue(settings.queue_size)
        self.reorder_buffer = []

    def open(self):
        try:
            self.sock = socket.create_connection((self.host, self.port))
        except Exception as identifier:
            print('[D] Failed to connect:', self.host, self.port, identifier)
            return
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)

    def close(self):
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            self.sock.close()
            self.sock = None
            self.iqueue.put(None)
        self.input_thread.join()
        self.output_thread.join()

    def handle_input(self):
        while self.sock:
            _found = False
            if len(self.reorder_buffer) == 0:
                _item = self.iqueue.get()
                if _item is None:
                    break
                if _item[0] <= self.tokenid:
                    print('[W] Received a duplicated packet, ignored.')
                    continue
                if _item[0] != self.tokenid + 1:
                    print('[W] Tokenid mismatch:', _item[0], 'expected:', self.tokenid + 1)
                    self.iqueue.put(_item)
                else:
                    _found = True
            else:
                for index in range(len(self.reorder_buffer)):
                    if self.reorder_buffer[index][0] == self.tokenid + 1:
                        _item = self.reorder_buffer.pop(index)
                        _found = True
                        break
            if not _found:
                try:
                    _item = find_packet(self.tokenid + 1, self.iqueue, self.reorder_buffer, settings.queue_size * 2)
                except queue.Empty:
                    print('[E] Packet loss: Timed out')
                    break
                except Exception as identifier:
                    print('[E] Packet loss:', identifier)
                    break

            self.tokenid = _item[0]
            try:
                self.sock.sendall(_item[1])
            except Exception:
                break
            if len(_item[1]) == 0:
                break
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        self.sock.close()
        print('[D] Input closed.')

    def handle_output(self):
        while self.sock:
            try:
                _d = self.sock.recv(settings.buffer_size)
                # print('[D] recv:', _d)
            except Exception:
                try:
                    self.oqueue.put_nowait(b'')
                except Exception:
                    pass
                break
            self.oqueue.put(_d)
            if len(_d) == 0:
                break
        self.iqueue.put(None)
        print('[D] Output closed.')


def server(host, port, max_sessions=None, buffer_size=None, queue_size=None):
    if max_sessions is not None:
        settings.max_sessions = max_sessions
    if buffer_size is not None:
        settings.buffer_size = buffer_size
    if queue_size is not None:
        settings.queue_size = queue_size

    rsa.generate()
    print('[I] Starting server mode.')
    print('[I] Listening on:', f'{host if host else "<any>"}:{port}')
    print('[I] Public key:')
    print(rsa.public_pem)
    uvicorn.run(
        app=app,
        host=host,
        port=port,
        timeout_keep_alive=30,
        log_level='error',
        h11_max_incomplete_event_size=1048576  # big enough to handle large cookies
    )
