"""Tests for deployment configuration files.

Validates Dockerfile, docker-compose.yml, Kubernetes manifests,
and locustfile.py for correctness and required content.
"""

import os
import ast
import yaml
from pathlib import Path

# All paths relative to project root
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
K8S_DIR = os.path.join(ROOT, "deploy", "k8s")


class TestDockerfile:
    """Validate Dockerfile structure and content."""

    def test_dockerfile_exists(self):
        """Dockerfile must exist at project root."""
        assert os.path.isfile(os.path.join(ROOT, "Dockerfile"))

    def test_multi_stage_build(self):
        """Dockerfile must use multi-stage build."""
        content = Path(ROOT, "Dockerfile").read_text(encoding="utf-8")
        # Must have at least two FROM statements
        from_count = content.count("FROM ")
        assert from_count >= 2, f"Expected multi-stage build, found {from_count} FROM"

    def test_builder_stage(self):
        """Dockerfile must have a builder stage."""
        content = Path(ROOT, "Dockerfile").read_text(encoding="utf-8")
        assert "AS builder" in content or "as builder" in content

    def test_runtime_stage(self):
        """Dockerfile must have a runtime stage."""
        content = Path(ROOT, "Dockerfile").read_text(encoding="utf-8")
        assert "AS runtime" in content or "as runtime" in content

    def test_python_slim_base(self):
        """Dockerfile must use python:3.11-slim."""
        content = Path(ROOT, "Dockerfile").read_text(encoding="utf-8")
        assert "python:3.11-slim" in content

    def test_expose_8080(self):
        """Dockerfile must expose port 8080."""
        content = Path(ROOT, "Dockerfile").read_text(encoding="utf-8")
        assert "EXPOSE 8080" in content

    def test_healthcheck(self):
        """Dockerfile must include HEALTHCHECK instruction."""
        content = Path(ROOT, "Dockerfile").read_text(encoding="utf-8")
        assert "HEALTHCHECK" in content

    def test_healthcheck_targets_health_endpoint(self):
        """HEALTHCHECK must target /v1/health."""
        content = Path(ROOT, "Dockerfile").read_text(encoding="utf-8")
        assert "/v1/health" in content

    def test_cmd_instruction(self):
        """Dockerfile must have CMD to run the server."""
        content = Path(ROOT, "Dockerfile").read_text(encoding="utf-8")
        assert "CMD" in content

    def test_runs_tests_in_builder(self):
        """Builder stage must run tests."""
        content = Path(ROOT, "Dockerfile").read_text(encoding="utf-8")
        assert "pytest" in content

    def test_runtime_consumes_builder_artifact(self):
        ## Runtime must install the wheel produced by the tested builder stage.
        content = Path(ROOT, "Dockerfile").read_text(encoding="utf-8")
        assert "COPY --from=builder /wheels /wheels" in content
        assert "pip wheel" in content
        assert "pip install --no-cache-dir /wheels/*.whl" in content


class TestDockerCompose:
    """Validate docker-compose.yml structure."""

    def test_file_exists(self):
        """docker-compose.yml must exist at project root."""
        assert os.path.isfile(os.path.join(ROOT, "docker-compose.yml"))

    def test_valid_yaml(self):
        """docker-compose.yml must be valid YAML."""
        with open(os.path.join(ROOT, "docker-compose.yml")) as f:
            data = yaml.safe_load(f)
        assert data is not None

    def test_services_defined(self):
        """Must define services section."""
        with open(os.path.join(ROOT, "docker-compose.yml")) as f:
            data = yaml.safe_load(f)
        assert "services" in data

    def test_mcp_monitor_service(self):
        """Must define mcp-monitor service."""
        with open(os.path.join(ROOT, "docker-compose.yml")) as f:
            data = yaml.safe_load(f)
        assert "mcp-monitor" in data["services"]

    def test_port_mapping(self):
        """Service must map port 8080."""
        with open(os.path.join(ROOT, "docker-compose.yml")) as f:
            data = yaml.safe_load(f)
        service = data["services"]["mcp-monitor"]
        assert "ports" in service
        assert "127.0.0.1:8080:8080" in service["ports"]

    def test_healthcheck(self):
        """Service must have healthcheck."""
        with open(os.path.join(ROOT, "docker-compose.yml")) as f:
            data = yaml.safe_load(f)
        service = data["services"]["mcp-monitor"]
        assert "healthcheck" in service

    def test_restart_policy(self):
        """Service must have restart policy."""
        with open(os.path.join(ROOT, "docker-compose.yml")) as f:
            data = yaml.safe_load(f)
        service = data["services"]["mcp-monitor"]
        assert service.get("restart") == "unless-stopped"

    def test_environment_variables(self):
        """Service must define environment variables."""
        with open(os.path.join(ROOT, "docker-compose.yml")) as f:
            data = yaml.safe_load(f)
        service = data["services"]["mcp-monitor"]
        assert "environment" in service
        env_list = service["environment"]
        env_names = [e.split("=")[0] for e in env_list]
        assert "MCP_LISTEN_PORT" in env_names
        assert "MCP_SHADOW_MODE" in env_names
        assert "MCP_API_KEY" in env_names


class TestKubernetesNamespace:
    """Validate namespace.yaml."""

    def test_file_exists(self):
        """namespace.yaml must exist."""
        assert os.path.isfile(os.path.join(K8S_DIR, "namespace.yaml"))

    def test_valid_yaml(self):
        """namespace.yaml must be valid YAML."""
        with open(os.path.join(K8S_DIR, "namespace.yaml")) as f:
            data = yaml.safe_load(f)
        assert data is not None

    def test_kind_is_namespace(self):
        """Must have kind: Namespace."""
        with open(os.path.join(K8S_DIR, "namespace.yaml")) as f:
            data = yaml.safe_load(f)
        assert data["kind"] == "Namespace"

    def test_api_version(self):
        """Must have apiVersion: v1."""
        with open(os.path.join(K8S_DIR, "namespace.yaml")) as f:
            data = yaml.safe_load(f)
        assert data["apiVersion"] == "v1"

    def test_name_is_mcp_monitor(self):
        """Namespace name must be mcp-monitor."""
        with open(os.path.join(K8S_DIR, "namespace.yaml")) as f:
            data = yaml.safe_load(f)
        assert data["metadata"]["name"] == "mcp-monitor"


class TestKubernetesConfigMap:
    """Validate configmap.yaml."""

    def test_file_exists(self):
        """configmap.yaml must exist."""
        assert os.path.isfile(os.path.join(K8S_DIR, "configmap.yaml"))

    def test_valid_yaml(self):
        """configmap.yaml must be valid YAML."""
        with open(os.path.join(K8S_DIR, "configmap.yaml")) as f:
            data = yaml.safe_load(f)
        assert data is not None

    def test_kind_is_configmap(self):
        """Must have kind: ConfigMap."""
        with open(os.path.join(K8S_DIR, "configmap.yaml")) as f:
            data = yaml.safe_load(f)
        assert data["kind"] == "ConfigMap"

    def test_api_version(self):
        """Must have apiVersion: v1."""
        with open(os.path.join(K8S_DIR, "configmap.yaml")) as f:
            data = yaml.safe_load(f)
        assert data["apiVersion"] == "v1"

    def test_has_mcp_env_vars(self):
        """ConfigMap must contain MCP_* environment variables."""
        with open(os.path.join(K8S_DIR, "configmap.yaml")) as f:
            data = yaml.safe_load(f)
        config_data = data["data"]
        assert "MCP_LISTEN_PORT" in config_data
        assert "MCP_SHADOW_MODE" in config_data
        assert "MCP_RATE_LIMIT_RPM" in config_data
        assert "MCP_LOG_LEVEL" in config_data


class TestKubernetesDeployment:
    """Validate deployment.yaml."""

    def test_file_exists(self):
        """deployment.yaml must exist."""
        assert os.path.isfile(os.path.join(K8S_DIR, "deployment.yaml"))

    def test_valid_yaml(self):
        """deployment.yaml must be valid YAML."""
        with open(os.path.join(K8S_DIR, "deployment.yaml")) as f:
            data = yaml.safe_load(f)
        assert data is not None

    def test_kind_is_deployment(self):
        """Must have kind: Deployment."""
        with open(os.path.join(K8S_DIR, "deployment.yaml")) as f:
            data = yaml.safe_load(f)
        assert data["kind"] == "Deployment"

    def test_api_version(self):
        """Must have apiVersion: apps/v1."""
        with open(os.path.join(K8S_DIR, "deployment.yaml")) as f:
            data = yaml.safe_load(f)
        assert data["apiVersion"] == "apps/v1"

    def test_replicas(self):
        """Must use one replica with the file-backed WAL PVC."""
        with open(os.path.join(K8S_DIR, "deployment.yaml")) as f:
            data = yaml.safe_load(f)
        assert data["spec"]["replicas"] == 1

    def test_resource_limits(self):
        """Container must have resource limits."""
        with open(os.path.join(K8S_DIR, "deployment.yaml")) as f:
            data = yaml.safe_load(f)
        container = data["spec"]["template"]["spec"]["containers"][0]
        limits = container["resources"]["limits"]
        assert limits["memory"] == "256Mi"
        assert limits["cpu"] == "500m"

    def test_liveness_probe(self):
        """Container must have liveness probe on /v1/health."""
        with open(os.path.join(K8S_DIR, "deployment.yaml")) as f:
            data = yaml.safe_load(f)
        container = data["spec"]["template"]["spec"]["containers"][0]
        probe = container["livenessProbe"]
        assert probe["httpGet"]["path"] == "/v1/health"
        assert probe["httpGet"]["port"] == 8080

    def test_readiness_probe(self):
        """Container must have readiness probe on /v1/ready."""
        with open(os.path.join(K8S_DIR, "deployment.yaml")) as f:
            data = yaml.safe_load(f)
        container = data["spec"]["template"]["spec"]["containers"][0]
        probe = container["readinessProbe"]
        assert probe["httpGet"]["path"] == "/v1/ready"
        assert probe["httpGet"]["port"] == 8080

    def test_env_from_configmap(self):
        """Container must use envFrom with configMapRef."""
        with open(os.path.join(K8S_DIR, "deployment.yaml")) as f:
            data = yaml.safe_load(f)
        container = data["spec"]["template"]["spec"]["containers"][0]
        env_from = container["envFrom"]
        config_ref_names = [
            e["configMapRef"]["name"] for e in env_from if "configMapRef" in e
        ]
        assert "mcp-monitor-config" in config_ref_names

    def test_api_key_from_secret(self):
        """Protected routes require MCP_API_KEY from a Kubernetes Secret."""
        with open(os.path.join(K8S_DIR, "deployment.yaml")) as f:
            data = yaml.safe_load(f)
        container = data["spec"]["template"]["spec"]["containers"][0]
        env = {item["name"]: item for item in container["env"]}
        secret_ref = env["MCP_API_KEY"]["valueFrom"]["secretKeyRef"]
        assert secret_ref["name"] == "mcp-monitor-secrets"
        assert secret_ref["key"] == "MCP_API_KEY"

    def test_data_volume_uses_persistent_volume_claim(self):
        """WAL/audit /data must not use ephemeral emptyDir storage."""
        with open(os.path.join(K8S_DIR, "deployment.yaml")) as f:
            data = yaml.safe_load(f)
        volumes = {v["name"]: v for v in data["spec"]["template"]["spec"]["volumes"]}
        assert (
            volumes["wal-data"]["persistentVolumeClaim"]["claimName"]
            == "mcp-monitor-data"
        )
        mounts = data["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
        data_mount = next(m for m in mounts if m["name"] == "wal-data")
        assert data_mount["mountPath"] == "/data"

    def test_container_security_context(self):
        """Container must run with reduced privileges."""
        with open(os.path.join(K8S_DIR, "deployment.yaml")) as f:
            data = yaml.safe_load(f)
        container = data["spec"]["template"]["spec"]["containers"][0]
        security_context = container["securityContext"]
        assert security_context["allowPrivilegeEscalation"] is False
        assert security_context["readOnlyRootFilesystem"] is True
        assert "ALL" in security_context["capabilities"]["drop"]

    def test_image_requires_registry_replacement_before_cluster_apply(self):
        ## The sample image tag must be explicitly documented as local-only.
        with open(os.path.join(K8S_DIR, "deployment.yaml")) as f:
            data = yaml.safe_load(f)
        container = data["spec"]["template"]["spec"]["containers"][0]
        assert container["image"] == "mcp-monitor:0.1.0"
        assert container["imagePullPolicy"] == "IfNotPresent"
        with open(os.path.join(K8S_DIR, "README.md")) as f:
            runbook = f.read()
        assert "update `image:` in `deployment.yaml`" in runbook


class TestKubernetesSecretExample:
    ## Validate secret.example.yaml is safe documentation, not a real Secret.

    def test_example_secret_is_not_applyable_secret(self):
        with open(os.path.join(K8S_DIR, "secret.example.yaml")) as f:
            data = yaml.safe_load(f)
        assert data["kind"] == "SecretTemplate"
        assert data["apiVersion"] == "docs.example/v1"
        assert data["requiredKeys"] == ["MCP_API_KEY"]
        assert "stringData" not in data


class TestKubernetesService:
    """Validate service.yaml."""

    def test_file_exists(self):
        """service.yaml must exist."""
        assert os.path.isfile(os.path.join(K8S_DIR, "service.yaml"))

    def test_valid_yaml(self):
        """service.yaml must be valid YAML."""
        with open(os.path.join(K8S_DIR, "service.yaml")) as f:
            data = yaml.safe_load(f)
        assert data is not None

    def test_kind_is_service(self):
        """Must have kind: Service."""
        with open(os.path.join(K8S_DIR, "service.yaml")) as f:
            data = yaml.safe_load(f)
        assert data["kind"] == "Service"

    def test_cluster_ip_type(self):
        """Service type must be ClusterIP."""
        with open(os.path.join(K8S_DIR, "service.yaml")) as f:
            data = yaml.safe_load(f)
        assert data["spec"]["type"] == "ClusterIP"

    def test_port_80_to_8080(self):
        """Service must map port 80 to targetPort 8080."""
        with open(os.path.join(K8S_DIR, "service.yaml")) as f:
            data = yaml.safe_load(f)
        port = data["spec"]["ports"][0]
        assert port["port"] == 80
        assert port["targetPort"] == 8080


class TestKubernetesHPA:
    """Validate hpa.yaml."""

    def test_file_exists(self):
        """hpa.yaml must exist."""
        assert os.path.isfile(os.path.join(K8S_DIR, "hpa.yaml"))

    def test_valid_yaml(self):
        """hpa.yaml must be valid YAML."""
        with open(os.path.join(K8S_DIR, "hpa.yaml")) as f:
            data = yaml.safe_load(f)
        assert data is not None

    def test_kind_is_hpa(self):
        """Must have kind: HorizontalPodAutoscaler."""
        with open(os.path.join(K8S_DIR, "hpa.yaml")) as f:
            data = yaml.safe_load(f)
        assert data["kind"] == "HorizontalPodAutoscaler"

    def test_api_version(self):
        """Must have apiVersion: autoscaling/v2."""
        with open(os.path.join(K8S_DIR, "hpa.yaml")) as f:
            data = yaml.safe_load(f)
        assert data["apiVersion"] == "autoscaling/v2"

    def test_min_replicas(self):
        """HPA must keep one replica for the single-writer WAL PVC."""
        with open(os.path.join(K8S_DIR, "hpa.yaml")) as f:
            data = yaml.safe_load(f)
        assert data["spec"]["minReplicas"] == 1

    def test_max_replicas(self):
        """HPA must not scale the single-writer WAL PVC deployment."""
        with open(os.path.join(K8S_DIR, "hpa.yaml")) as f:
            data = yaml.safe_load(f)
        assert data["spec"]["maxReplicas"] == 1

    def test_cpu_target_utilization(self):
        """HPA must target 70% CPU utilization."""
        with open(os.path.join(K8S_DIR, "hpa.yaml")) as f:
            data = yaml.safe_load(f)
        metrics = data["spec"]["metrics"]
        cpu_metric = next(
            m
            for m in metrics
            if m["type"] == "Resource" and m["resource"]["name"] == "cpu"
        )
        assert cpu_metric["resource"]["target"]["averageUtilization"] == 70

    def test_targets_deployment(self):
        """HPA must target the mcp-monitor Deployment."""
        with open(os.path.join(K8S_DIR, "hpa.yaml")) as f:
            data = yaml.safe_load(f)
        ref = data["spec"]["scaleTargetRef"]
        assert ref["kind"] == "Deployment"
        assert ref["name"] == "mcp-monitor"


class TestLocustfile:
    """Validate locustfile.py for load testing."""

    def test_file_exists(self):
        """locustfile.py must exist at project root."""
        assert os.path.isfile(os.path.join(ROOT, "locustfile.py"))

    def test_imports_locust(self):
        """locustfile.py must import from locust."""
        content = Path(ROOT, "locustfile.py").read_text(encoding="utf-8")
        assert "from locust import" in content or "import locust" in content

    def test_defines_http_user(self):
        """locustfile.py must define an HttpUser subclass."""
        content = Path(ROOT, "locustfile.py").read_text(encoding="utf-8")
        assert "HttpUser" in content

    def test_has_task_decorator(self):
        """locustfile.py must use @task decorator."""
        content = Path(ROOT, "locustfile.py").read_text(encoding="utf-8")
        assert "@task" in content

    def test_exercises_inspect_call(self):
        """Must test /v1/inspect_call endpoint."""
        content = Path(ROOT, "locustfile.py").read_text(encoding="utf-8")
        assert "/v1/inspect_call" in content

    def test_exercises_inspect_output(self):
        """Must test /v1/inspect_output endpoint."""
        content = Path(ROOT, "locustfile.py").read_text(encoding="utf-8")
        assert "/v1/inspect_output" in content

    def test_exercises_health_check(self):
        """Must test /v1/health endpoint."""
        content = Path(ROOT, "locustfile.py").read_text(encoding="utf-8")
        assert "/v1/health" in content

    def test_documents_target_throughput(self):
        """Must document 5000 req/s target."""
        content = Path(ROOT, "locustfile.py").read_text(encoding="utf-8")
        assert "5000" in content

    def test_valid_python_syntax(self):
        """locustfile.py must be valid Python."""
        filepath = os.path.join(ROOT, "locustfile.py")
        with open(filepath) as f:
            source = f.read()
        # This will raise SyntaxError if invalid
        ast.parse(source)

    def test_has_realistic_payloads(self):
        """Must have realistic payloads with name, server_id, arguments."""
        content = Path(ROOT, "locustfile.py").read_text(encoding="utf-8")
        assert '"name"' in content
        assert '"server_id"' in content
        assert '"arguments"' in content
