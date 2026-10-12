# policy/k8s_security.rego
package main

# Rule 1: Deny if container runs as root
deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.runAsNonRoot == true
  msg := sprintf("Deployment '%v' container '%v' must set securityContext.runAsNonRoot to true", [input.metadata.name, container.name])
}

# Rule 2: Deny if root filesystem is not read-only
deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.readOnlyRootFilesystem == true
  msg := sprintf("Deployment '%v' container '%v' must set securityContext.readOnlyRootFilesystem to true", [input.metadata.name, container.name])
}

# Rule 3: Deny if resource limits are missing
deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.resources.limits
  msg := sprintf("Deployment '%v' container '%v' is missing resource limits", [input.metadata.name, container.name])
}