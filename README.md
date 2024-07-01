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

HTTPS is unnecessary since your proxy may block self-signed server certificates.
Even with a formal certificate, the proxy may still decrypt the SSL/TLS layer by using fake certificates,
and the data is encrypted (again, by this tool) anyway.

If there is still any concern, put the server behind the SSL/TLS endpoint.

## Problems

The connection WILL be slow, and may not be stable too.

Since HTTP is stateless,
it's better to use this tool with other "real" tunnel protocols, such as SSH, that maintain consistent connections,
otherwise, it may consume a lot of TCP sessions, which is not good and might be suspected.

## Requirements

- Python 3.8+
  - [requests](https://pypi.org/project/requests/) (for easy HTTP session handling)
  - [cryptography](https://pypi.org/project/cryptography/)
  - [fastapi-slim](https://pypi.org/project/fastapi-slim/) (for easy HTTP server implementation)
  - [uvicorn](https://pypi.org/project/uvicorn/) (for easy HTTP server implementation)
- OS: Linux, Windows, MacOS(not tested)

## Installation

```bash
pip install http-tunnel
```

## Usage

To start server:

```bash
http-tunnel -s
```

To start client:

```bash
http-tunnel -c
```

For more information:

```bash
http-tunnel --help
```

## Still working on

1. Support other request methods (default will use GET only).
   1. ~~POST~~
   2. ~~PUT~~
   3. ~~DELETE~~
   4. ~~PATCH~~
   5. WebSockets
2. Support UDP.

## As always

Use at your own risk and responsibility.
