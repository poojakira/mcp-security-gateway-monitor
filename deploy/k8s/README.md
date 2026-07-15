# Kubernetes Deployment

This directory contains a conservative sample deployment for the MCP Security Gateway Monitor.

## Required Secret

Create `mcp-monitor-secrets` before applying the deployment. Do not commit a real API key.

```bash
kubectl apply -f deploy/k8s/namespace.yaml
MCP_API_KEY="$(openssl rand -hex 32)"
kubectl create secret generic mcp-monitor-secrets \
  --namespace mcp-monitor \
  --from-literal=MCP_API_KEY="$MCP_API_KEY"
```

`secret.example.yaml` is documentation-only and intentionally not an applyable Kubernetes Secret. Use `kubectl create secret` or your cluster secret manager for the real value.

## Image

Build and push the image to a registry your cluster can pull, then update `image:` in `deployment.yaml`.

```bash
docker build -t registry.example.com/mcp-monitor:0.1.0 .
docker push registry.example.com/mcp-monitor:0.1.0
```

## Apply

```bash
kubectl apply -f deploy/k8s/configmap.yaml
kubectl apply -f deploy/k8s/pvc.yaml
kubectl apply -f deploy/k8s/deployment.yaml
kubectl apply -f deploy/k8s/service.yaml
kubectl apply -f deploy/k8s/hpa.yaml
```

## Durability And Scaling

The sample deployment uses one replica and a `ReadWriteOnce` PVC for `/data` because the local WAL and audit log append to files and are not safe for concurrent multi-pod writes to the same path. `hpa.yaml` is pinned at one replica for that reason. For high availability, move audit/WAL persistence to an external backend or replace the Deployment with a StatefulSet that gives each pod its own PVC.

## Verify

```bash
kubectl get pods -n mcp-monitor
kubectl logs -n mcp-monitor deploy/mcp-monitor
kubectl port-forward -n mcp-monitor svc/mcp-monitor 8080:80
curl http://127.0.0.1:8080/v1/health
curl http://127.0.0.1:8080/v1/ready
```




