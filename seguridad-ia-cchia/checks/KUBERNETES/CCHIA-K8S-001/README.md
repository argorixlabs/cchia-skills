# CCHIA-K8S-001 — Privilegios de workloads

Detecta siete configuraciones explícitas de alto riesgo en manifests YAML. No consulta el clúster. Helm/Kustomize
deben renderizarse antes para aumentar cobertura; admission policy y estado runtime son evidencia separada.
