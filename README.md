# http-tunnel

Tunneling all sockets by using regular HTTP requests.

## Why

If you always suffered from the limitations of proxy or firewall that cannot be avoided,
then this tool MIGHT be useful for you.

## How it works

It is a pair of HTTP client/server programs.
The client also acts as a server, capturing all incoming sockets and sending them to the server.
The server then sends the received socket data to the target server.

All data between the client and server is encrypted and wrapped in HTTP requests.

HTTPS is supported, but your proxy may block self-signed server certificates.
Even with a formal certificate, the proxy may still decrypt the SSL/TLS layer by using fake certificates,
and the data is encrypted (again, by this tool) anyway.

HTTPS may be only necessary for WebSocket since it will connect by using the CONNECT method via proxy,
which is probably not allowed other than HTTPS.

If there is still any concern, put the server behind a firewall or any reverse proxy that can handle SSL/TLS connections.

## Problems

The connection WILL be slow, and may not be stable too.

Although the WebSocket method can do way better performance than others, it may not be suitable for all situations.

Since HTTP is stateless,
it's better to use this tool with other "real" tunnel protocols, such as SSH, that maintain consistent connections,
otherwise, it may consume a lot of sessions, which is not efficient and might be suspected.

## Requirements

- Python 3.8+
  - [requests](https://pypi.org/project/requests/), [pysocks](https://pypi.org/project/PySocks/) (for easy client handling)
  - [fastapi-slim](https://pypi.org/project/fastapi-slim/), [uvicorn](https://pypi.org/project/uvicorn/) (for easy server implementation)
  - [websockets](https://pypi.org/project/websockets/) (for WebSocket implementation)
  - [cryptography](https://pypi.org/project/cryptography/)
- OS: Linux, Windows, MacOS(not tested)

## Installation

```bash
pip install http-tunnel
```

## Usage

- To start server:

  ```bash
  http-tunnel -s
  ```

- To start client:

  ```bash
  http-tunnel -c
  ```

  **Note:** To use proxy, set the `HTTP_PROXY` or `HTTPS_PROXY` environment variable.

- For more information:

  ```bash
  http-tunnel --help
  ```

## Still working on

1. ~~Support other request methods.~~
   - [x] ~~POST~~
   - [x] ~~PUT~~
   - [x] ~~DELETE~~
   - [x] ~~PATCH~~
   - [x] ~~WebSocket~~
2. Support UDP.

## As always

Use at your own risk and responsibility.
