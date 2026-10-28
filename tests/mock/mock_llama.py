# llama.cpp-style OpenAI endpoint emulating Qwen3Guard-Gen output for the W08 e2e test.
# Unsafe/Violent if the user text contains BLOCKME, Controversial on MAYBE, else Safe.
import json, sys
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

KEY = "Bearer test-guard-key"


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    wbufsize = 1 << 16  # one write per response; avoids Nagle/delayed-ACK stalls skewing timings

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        if self.headers.get("Authorization") != KEY:
            return self._json(401, {"error": {"message": "Invalid API Key", "type": "authentication_error", "code": 401}})
        text = body["messages"][0]["content"]
        if "BLOCKME" in text:
            out = "Safety: Unsafe\nCategories: Violent"
        elif "MAYBE" in text:
            out = "Safety: Controversial\nCategories: Politically Sensitive Topics"
        else:
            out = "Safety: Safe\nCategories: None"
        self._json(200, {"model": "Qwen3Guard-Gen-0.6B", "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": out}}]})

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
