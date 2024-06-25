class Config(object):
    def __init__(self) -> None:
        self.forward_url = 'http://localhost:8080'
        self.forward_srv = 'localhost:22'
        self.max_sessions = 10
        self.buffer_size = 32768
        self.queue_size = 10
