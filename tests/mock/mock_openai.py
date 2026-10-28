# OpenAI-compatible upstream for the W04 rate-limit test.
#   model "ok"          -> 200 JSON completion
#   model "fail"        -> 500
#   model "slow-stream" -> SSE, 8 events 1s apart
import json, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler


HITS = [0]


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        # GET /hits -> number of completions served (used to prove denied requests never arrive)
        self._json(200, {"hits": HITS[0]})

    def do_POST(self):
        HITS[0] += 1
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0) or 0)) or b"{}")
        model = body.get("model", "")
        if model == "fail":
            return self._json(500, {"error": {"message": "mock failure", "type": "server_error"}})
        if model == "slow-stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i in range(8):
                chunk = {"id": "c", "object": "chat.completion.chunk", "created": 0, "model": model,
                         "choices": [{"index": 0, "delta": {"content": str(i)}, "finish_reason": None}]}
                self._chunk(("data: " + json.dumps(chunk) + "\n\n").encode())
                time.sleep(1)
            self._chunk(b"data: [DONE]\n\n")
            self.wfile.write(b"0\r\n\r\n")
            return
        self._json(200, {"id": "c", "object": "chat.completion", "created": 0, "model": model,
                         "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
                         "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})

    def _chunk(self, b):
        self.wfile.write(b"%x\r\n%s\r\n" % (len(b), b))
        self.wfile.flush()

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
