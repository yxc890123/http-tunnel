from typing import Union
from fastapi import FastAPI, Cookie, Body
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


class Forwarder(object):
    def __init__(self, host: str, port: int) -> None:
        self.cipher: Crypto_AES = None
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
        self.watchdog_timer = threading.Event()
        self.watchdog_thread = None

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
            self.watchdog_timer.set()

        while not self.oqueue.empty():
            try:
                self.oqueue.get_nowait()
            except Exception:
                break

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
                    _item = find_packet(self.tokenid + 1, self.iqueue, self.reorder_buffer, settings.reorder_limit)
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
        if self.sock:
            try:
                self.sock.sendall(b'')
                self.sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            self.sock.close()
            self.sock = None
            self.watchdog_timer.set()
        print('[D] Input closed.')

    def handle_output(self):
        while self.sock:
            try:
                _d = self.sock.recv(settings.buffer_size)
                # print('[D] recv:', _d)
            except Exception:
                self.oqueue.put(b'')
                break
            self.oqueue.put(_d)
            if len(_d) == 0:
                break
        self.iqueue.put(None)
        print('[D] Output closed.')

    def watchdog(self):
        while self.sock:
            if self.watchdog_timer.wait(30.0):
                self.watchdog_timer.clear()
            else:
                print('[E] Session timed out.')
                self.close()


def clean_up():
    for _sid in list(sessions.keys()):
        _session: Forwarder = sessions[_sid]
        if not _session.sock:
            _session.watchdog_thread.join()
            sessions.pop(_sid, None)
            print('[I] Deleted dead session:', _sid)


@app.get('/')
def root():
    return PlainTextResponse(rsa.public_pem, headers={'connection': 'close'})


@app.get('/api/login')
def login(
    secret: str = Cookie(default=...),
    token: str = Cookie(default=...)
):
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
        _forward_srv = _aes.decrypt(token)
    except Exception as identifier:
        print('[E] Failed to decrypt token:', identifier)
        return JSONResponse(
            {'error': 'Invalid token'},
            status_code=400,
            headers={'connection': 'close'}
        )

    try:
        _forward_srv = _forward_srv.decode().split(':')
        _host = _forward_srv[0]
        _port = int(_forward_srv[1])
    except Exception as identifier:
        print('[D] Invalid host/port in token:', identifier)
        return JSONResponse(
            {'error': 'Invalid token'},
            status_code=400,
            headers={'connection': 'close'}
        )

    clean_up()
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
        _session.watchdog_thread = threading.Thread(target=_session.watchdog)
        _session.watchdog_thread.start()
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


def put_iqueue(session: Forwarder, tokenid, token):
    try:
        tokenid = session.cipher.decrypt(tokenid)
    except Exception as identifier:
        print('[E] Failed to decrypt tokenid:', identifier)
        return JSONResponse(
            {'error': 'Invalid tokenid'},
            status_code=400,
            headers={'connection': 'close'}
        )

    # print('[D] received tokenid:', tokenid)
    for _id, _encrypted_token in zip(tokenid.decode().split(' '), token.split(' ')):
        try:
            _id = int(_id)
        except Exception as identifier:
            print('[E] Invalid tokenid in request:', identifier)
            return JSONResponse(
                {'error': 'Invalid token id'},
                status_code=400,
                headers={'connection': 'close'}
            )
        try:
            _token = session.cipher.decrypt(_encrypted_token)
        except Exception as identifier:
            print('[E] Failed to decrypt token:', identifier)
            return JSONResponse(
                {'error': 'Invalid token'},
                status_code=400,
                headers={'connection': 'close'}
            )
        if not session.sock:
            break
        session.iqueue.put((int(_id), _token))
        if len(_token) == 0:
            break


def get_oqueue(session: Forwarder, sid, timeout):
    try:
        _outq_item = session.oqueue.get(timeout=timeout)
    except Exception:
        if not session.sock:
            session.res_tokenid += 1
            _res = JSONResponse(
                {
                    'error': None,
                    'tokenid': session.cipher.encrypt(str(session.res_tokenid).encode()),
                    'token': session.cipher.encrypt(b'')
                },
                headers={'connection': 'keep-alive'}
            )
            _res.set_cookie(key='sid', value=sid, path='/api/')
            session.watchdog_timer.set()
            return _res
        _res = JSONResponse(
            {'error': None},
            status_code=202,
            headers={'connection': 'keep-alive'}
        )
        _res.set_cookie(key='sid', value=sid, path='/api/')
        session.watchdog_timer.set()
        return _res

    session.res_tokenid += 1
    _res_tokenid = [str(session.res_tokenid)]
    _res_token = [session.cipher.encrypt(_outq_item)]
    while not session.oqueue.empty():
        try:
            _outq_item = session.oqueue.get_nowait()
        except Exception:
            break
        session.res_tokenid += 1
        _res_tokenid.append(str(session.res_tokenid))
        _res_token.append(session.cipher.encrypt(_outq_item))
        if len(_res_tokenid) >= settings.queue_size:
            break

    # print('[D] sending tokenid:', sid, _res_tokenid)
    _res = JSONResponse(
        {
            'error': None,
            'tokenid': session.cipher.encrypt(' '.join(_res_tokenid).encode()),
            'token': ' '.join(_res_token)
        },
        headers={'connection': 'keep-alive'}
    )
    _res.set_cookie(key='sid', value=sid, path='/api/')
    # _res.set_cookie(key='tokenid', value=session.cipher.encrypt(' '.join(_res_tokenid)), path='/api/')
    # _res.set_cookie(key='token', value=' '.join(_res_token), path='/api/')
    session.watchdog_timer.set()
    return _res


@app.get('/api/session')
def session(
    sid: str = Cookie(default=...),
    nonce: str = Cookie(default=...),
    tokenid: Union[str, None] = Cookie(default=None),
    token: Union[str, None] = Cookie(default=None)
):
    if sid not in sessions:
        return JSONResponse(
            {'error': 'Session ID not found'},
            status_code=404,
            headers={'connection': 'close'}
        )
    if type(tokenid) is not type(token):
        return JSONResponse(
            {'error': 'Invalid token'},
            status_code=400,
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

    if not _session.sock:
        clean_up()
        return JSONResponse(
            {'error': 'Session already closed'},
            status_code=409,
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

        _timeout = 0.02

        _res = put_iqueue(_session, tokenid, token)
        if _res is not None:
            return _res

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

    return get_oqueue(_session, sid, _timeout)


@app.post('/api/session')
@app.put('/api/session')
@app.delete('/api/session')
@app.patch('/api/session')
# content-type: application/json required
def session_with_body(
    sid: str = Cookie(default=...),
    nonce: str = Cookie(default=...),
    tokenid: str = Body(default=...),
    token: str = Body(default=...)
):
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

    if not _session.sock:
        clean_up()
        return JSONResponse(
            {'error': 'Session already closed'},
            status_code=409,
            headers={'connection': 'close'}
        )

    if _nonce <= _session.put_nonce:
        print('[E] Received duplicated nonce.')
        return JSONResponse(
            {'error': 'Duplicated nonce'},
            status_code=403,
            headers={'connection': 'close'}
        )
    else:
        _session.put_nonce = _nonce

    _res = put_iqueue(_session, tokenid, token)
    if _res is not None:
        return _res

    return get_oqueue(_session, sid, 0.02)


@app.get('/api/logout')
def logout(
    sid: str = Cookie(default=...),
    nonce: str = Cookie(default=...)
):
    print('[I] Closing session:', sid)
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
    _session.watchdog_thread.join()
    sessions.pop(sid, None)
    clean_up()
    return JSONResponse({'error': None}, headers={'connection': 'close'})


def server(host, port, max_sessions=None, buffer_size=None, queue_size=None, reorder_limit=None):
    if max_sessions is not None:
        settings.max_sessions = max_sessions
    if buffer_size is not None:
        settings.buffer_size = buffer_size
    if queue_size is not None:
        settings.queue_size = queue_size
    if reorder_limit is not None:
        settings.reorder_limit = reorder_limit

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
