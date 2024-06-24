# http-tunnel

Tunneling all sockets by using regular HTTP requests.

## Why

If you always suffered from the limitations of proxy or firewall that cannot be avoided,

then this tool MIGHT be useful for you.

## How it works

It is a pair of HTTP client/server programs.

The client also acts as a server, capturing all incoming sockets and sending them to the server.

The server then sends the received socket data to the target server.

All data between the client and server is encrypted and wrapped in GET requests.

<br/>

HTTPS is unnecessary since your proxy may block self-signed server certificates,

and even with a formal certificate, it may still decrypt the SSL/TLS layer by using fake certificates,

and the data is encrypted (again, by this tool) anyway.

If there is still any concern, put the server behind the SSL/TLS endpoint.

## Problems

1. The connection WILL be slow, and may not be stable too.
2. UDP is not supported (yet).

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

## As always

Use at your own risk and responsibility.
