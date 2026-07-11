"""Locust load test for MCP Security Gateway Monitor.

Target: 5000 requests/second sustained throughput.

Run with:
    locust -f locustfile.py --host=http://localhost:8080 --users 500 --spawn-rate 50

For headless mode targeting 5000 req/s:
    locust -f locustfile.py --host=http://localhost:8080 \
        --users 1000 --spawn-rate 100 --headless --run-time 60s
"""

from locust import HttpUser, task, between


class MCPLoadUser(HttpUser):
    """Simulates load on the MCP Security Gateway Monitor API.

    Exercises all production endpoints with realistic payloads including
    clean tool calls, injection attempts, and output inspection.
    """

    wait_time = between(0.01, 0.05)

    @task(5)
    def inspect_call_clean(self):
        """Normal tool call - should be allowed."""
        payload = {
            "name": "read_file",
            "server_id": "vscode-server-01",
            "arguments": {
                "path": "/home/user/documents/report.txt",
            },
        }
        self.client.post("/v1/inspect_call", json=payload)

    @task(3)
    def inspect_call_injection(self):
        """Injection attempt - should be flagged."""
        payload = {
            "name": "execute_command",
            "server_id": "tool-server-02",
            "arguments": {
                "command": "cat /etc/passwd; rm -rf /",
                "working_dir": "/tmp",
            },
        }
        self.client.post("/v1/inspect_call", json=payload)

    @task(3)
    def inspect_call_path_traversal(self):
        """Path traversal attempt - should be flagged."""
        payload = {
            "name": "read_file",
            "server_id": "file-server-03",
            "arguments": {
                "path": "../../../../etc/shadow",
            },
        }
        self.client.post("/v1/inspect_call", json=payload)

    @task(2)
    def inspect_output(self):
        """Output inspection for data exfiltration detection."""
        payload = {
            "tool_name": "database_query",
            "output": {
                "result": "user_id=123, email=admin@corp.com, ssn=123-45-6789",
                "rows_affected": 1,
            },
        }
        self.client.post("/v1/inspect_output", json=payload)

    @task(2)
    def inspect_output_clean(self):
        """Clean output - should pass inspection."""
        payload = {
            "tool_name": "list_files",
            "output": {
                "files": ["README.md", "src/main.py", "tests/test_main.py"],
                "count": 3,
            },
        }
        self.client.post("/v1/inspect_output", json=payload)

    @task(1)
    def health_check(self):
        """Health check endpoint."""
        self.client.get("/v1/health")

    @task(1)
    def readiness_check(self):
        """Readiness probe endpoint."""
        self.client.get("/v1/ready")

    @task(1)
    def metrics(self):
        """Metrics endpoint."""
        self.client.get("/v1/metrics")
