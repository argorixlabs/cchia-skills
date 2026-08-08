# CCHIA-GCP-IAM-002 — IAM GCP en Terraform

Busca `roles/owner`, `roles/editor`, `allUsers` y `allAuthenticatedUsers`. No ejecuta Terraform ni consulta
GCP. Un `PASS` solo cubre el código recibido: la herencia, el drift y los grants manuales requieren evidencia
cloud read-only adicional.
