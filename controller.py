"""
Kubernetes Admission Controller (Policy-as-Code)
Validates Kubernetes manifests (YAML/JSON) against security best practices
before they hit the cluster.

Can run in two modes:
  1. CLI / CI-gate:  python controller.py manifests/
  2. Validating Admission Webhook (Flask required):  python controller.py --serve

Author: Mohith Vasamsetti (CyberEnthusiastic)
"""
import os
import re
import sys
import json
import argparse
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional

from report_generator import generate_html

# Minimal YAML loader (no PyYAML dependency - handles multi-doc)
# If PyYAML is available, use it. Otherwise use a simple parser that
# works for the common k8s manifest subset.
try:
    import yaml  # type: ignore
    def load_yaml(text):
        return list(yaml.safe_load_all(text))
except ImportError:
    from yaml_mini import safe_load_all as _sla  # local shim
    def load_yaml(text):
        return list(_sla(text))


# -------------------------------------------------------------
# Rule catalog: CIS Kubernetes Benchmark + Pod Security Standards
# -------------------------------------------------------------
RULES = [
    {
        "id": "K8S-001",
        "name": "Privileged container (privileged: true)",
        "severity": "CRITICAL",
        "confidence": 0.99,
        "cis": "CIS K8s 5.2.1",
        "remediation": "Set securityContext.privileged=false. Privileged containers break the container isolation boundary.",
    },
    {
        "id": "K8S-002",
        "name": "Host namespace sharing (hostNetwork/hostPID/hostIPC=true)",
        "severity": "CRITICAL",
        "confidence": 0.98,
        "cis": "CIS K8s 5.2.2-5.2.4",
        "remediation": "Never share host namespaces. Remove hostNetwork/hostPID/hostIPC or set to false.",
    },
    {
        "id": "K8S-003",
        "name": "Running as root (runAsUser=0 or runAsNonRoot unset)",
        "severity": "HIGH",
        "confidence": 0.90,
        "cis": "CIS K8s 5.2.6",
        "remediation": "securityContext: { runAsNonRoot: true, runAsUser: 10001 }",
    },
    {
        "id": "K8S-004",
        "name": "Dangerous capability (NET_ADMIN, SYS_ADMIN, SYS_PTRACE, etc.)",
        "severity": "HIGH",
        "confidence": 0.95,
        "cis": "CIS K8s 5.2.9",
        "remediation": "Drop ALL then add ONLY the caps you need. Never add SYS_ADMIN.",
    },
    {
        "id": "K8S-005",
        "name": "Capabilities not dropped (drop: [ALL] missing)",
        "severity": "MEDIUM",
        "confidence": 0.85,
        "cis": "CIS K8s 5.2.9",
        "remediation": "securityContext.capabilities.drop: ['ALL']",
    },
    {
        "id": "K8S-006",
        "name": "Writable root filesystem (readOnlyRootFilesystem != true)",
        "severity": "MEDIUM",
        "confidence": 0.85,
        "cis": "CIS K8s 5.2.10",
        "remediation": "securityContext.readOnlyRootFilesystem: true. Use emptyDir volumes for writable paths.",
    },
    {
        "id": "K8S-007",
        "name": "allowPrivilegeEscalation != false",
        "severity": "HIGH",
        "confidence": 0.92,
        "cis": "CIS K8s 5.2.5",
        "remediation": "securityContext.allowPrivilegeEscalation: false",
    },
    {
        "id": "K8S-008",
        "name": "Image tag is 'latest' or missing (non-immutable)",
        "severity": "MEDIUM",
        "confidence": 0.88,
        "cis": "CIS K8s 5.7.4",
        "remediation": "Pin to a digest (@sha256:...) or a specific semver tag. Never use :latest in production.",
    },
    {
        "id": "K8S-009",
        "name": "No resource limits (DoS risk)",
        "severity": "MEDIUM",
        "confidence": 0.80,
        "cis": "CIS K8s 5.7.2",
        "remediation": "Set resources.limits.cpu and resources.limits.memory for every container.",
    },
    {
        "id": "K8S-010",
        "name": "Default ServiceAccount used (or automountServiceAccountToken=true)",
        "severity": "MEDIUM",
        "confidence": 0.75,
        "cis": "CIS K8s 5.1.5",
        "remediation": "Create a dedicated ServiceAccount with only the RBAC it needs, set automountServiceAccountToken=false by default.",
    },
    {
        "id": "K8S-011",
        "name": "Secret mounted via env var (rotation/leak risk)",
        "severity": "LOW",
        "confidence": 0.70,
        "cis": "CIS K8s 5.4.1",
        "remediation": "Mount secrets as files (volumeMounts) instead of env vars when possible.",
    },
    {
        "id": "K8S-012",
        "name": "Docker socket / host path mounted",
        "severity": "CRITICAL",
        "confidence": 0.98,
        "cis": "CIS K8s 5.7.1",
        "remediation": "Never mount /var/run/docker.sock or / into a container. That is a node takeover vector.",
    },
    {
        "id": "K8S-013",
        "name": "No liveness/readiness probe defined",
        "severity": "LOW",
        "confidence": 0.70,
        "cis": "Best practice",
        "remediation": "Add livenessProbe and readinessProbe so k8s can restart/unroute sick pods.",
    },
    {
        "id": "K8S-014",
        "name": "NetworkPolicy missing for namespace (default-allow)",
        "severity": "MEDIUM",
        "confidence": 0.80,
        "cis": "CIS K8s 5.3.2",
        "remediation": "Apply a default-deny NetworkPolicy per namespace and whitelist required flows.",
    },
    {
        "id": "K8S-015",
        "name": "Image from untrusted registry (no docker.io/quay.io/ghcr.io/gcr.io)",
        "severity": "MEDIUM",
        "confidence": 0.75,
        "cis": "Best practice",
        "remediation": "Use only approved/signed registries. Integrate with Cosign / Sigstore for image verification.",
    },
]

DANGEROUS_CAPS = {
    "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE",
    "NET_RAW", "DAC_READ_SEARCH", "SYS_BOOT",
}

TRUSTED_REGISTRY_HINTS = (
    "docker.io/", "quay.io/", "ghcr.io/", "gcr.io/",
    "mcr.microsoft.com/", "registry.k8s.io/", "public.ecr.aws/",
)


@dataclass
class Finding:
    id: str
    name: str
    severity: str
    confidence: float
    cis: str
    file: str
    kind: str
    namespace: str
    resource_name: str
    container: str
    risk_score: float
    evidence: str
    remediation: str
    suggested_fix: str = ""


def rule(rid: str) -> dict:
    return next(r for r in RULES if r["id"] == rid)


def risk_score(r: dict, context_bonus: float = 0.0) -> float:
    base = r["confidence"] * 60
    sev_bonus = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 3, "LOW": 0}
    s = base + sev_bonus.get(r["severity"], 0) + context_bonus
    return round(min(100.0, max(0.0, s)), 1)


def mk(r, file, kind, ns, name, container, evidence, fix=""):
    return Finding(
        id=r["id"], name=r["name"], severity=r["severity"],
        confidence=r["confidence"], cis=r["cis"],
        file=file, kind=kind, namespace=ns or "default",
        resource_name=name, container=container or "",
        risk_score=risk_score(r), evidence=evidence,
        remediation=r["remediation"], suggested_fix=fix,
    )


# -------------------------------------------------------------
# Manifest inspection
# -------------------------------------------------------------
def get_pod_spec(doc: dict):
    """Return (pod_spec, kind) for any workload kind."""
    kind = doc.get("kind", "")
    if kind in ("Pod",):
        return doc.get("spec", {}), kind
    if kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"):
        return doc.get("spec", {}).get("template", {}).get("spec", {}), kind
    if kind == "CronJob":
        return (doc.get("spec", {}).get("jobTemplate", {})
                .get("spec", {}).get("template", {}).get("spec", {})), kind
    return None, kind


def check_pod(doc: dict, file: str) -> List[Finding]:
    findings: List[Finding] = []
    pod_spec, kind = get_pod_spec(doc)
    if pod_spec is None:
        return findings

    meta = doc.get("metadata", {}) or {}
    name = meta.get("name", "<unnamed>")
    ns = meta.get("namespace", "default")

    if pod_spec.get("hostNetwork") or pod_spec.get("hostPID") or pod_spec.get("hostIPC"):
        flags = [k for k in ("hostNetwork", "hostPID", "hostIPC") if pod_spec.get(k)]
        findings.append(mk(rule("K8S-002"), file, kind, ns, name, "",
                           f"Pod uses host namespaces: {', '.join(flags)}",
                           "Remove hostNetwork/hostPID/hostIPC or set to false."))

    # ServiceAccount checks
    sa = pod_spec.get("serviceAccountName") or pod_spec.get("serviceAccount")
    if not sa or sa == "default":
        findings.append(mk(rule("K8S-010"), file, kind, ns, name, "",
                           f"serviceAccountName={sa or 'default'}",
                           "serviceAccountName: my-app-sa (create with minimal RBAC)"))

    # Host-path volumes / docker socket
    for v in pod_spec.get("volumes", []) or []:
        hp = (v.get("hostPath") or {}).get("path", "")
        if hp in ("/", "/var/run/docker.sock", "/etc", "/root", "/var/run"):
            findings.append(mk(rule("K8S-012"), file, kind, ns, name, "",
                               f"volume '{v.get('name','?')}' hostPath={hp}",
                               "Use a PVC or emptyDir, never mount docker.sock or /"))

    # Containers
    for c in (pod_spec.get("containers") or []) + (pod_spec.get("initContainers") or []):
        findings.extend(check_container(c, doc, pod_spec, file, kind, ns, name))

    return findings


def check_container(c: dict, doc: dict, pod_spec: dict, file: str, kind: str, ns: str, name: str) -> List[Finding]:
    f: List[Finding] = []
    cname = c.get("name", "<noname>")
    sc = c.get("securityContext", {}) or {}
    pod_sc = pod_spec.get("securityContext", {}) or {}
    image = c.get("image", "")

    if sc.get("privileged") is True:
        f.append(mk(rule("K8S-001"), file, kind, ns, name, cname,
                    "securityContext.privileged=true",
                    "securityContext: { privileged: false }"))
    if sc.get("allowPrivilegeEscalation") is not False:
        f.append(mk(rule("K8S-007"), file, kind, ns, name, cname,
                    f"allowPrivilegeEscalation={sc.get('allowPrivilegeEscalation', 'unset')}",
                    "securityContext: { allowPrivilegeEscalation: false }"))
    ru = sc.get("runAsUser", pod_sc.get("runAsUser"))
    nr = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
    if ru == 0 or nr is not True:
        f.append(mk(rule("K8S-003"), file, kind, ns, name, cname,
                    f"runAsUser={ru}, runAsNonRoot={nr}",
                    "runAsNonRoot: true, runAsUser: 10001"))
    caps = (sc.get("capabilities") or {})
    added = [a.upper() for a in (caps.get("add") or [])]
    dropped = [d.upper() for d in (caps.get("drop") or [])]
    bad = [x for x in added if x in DANGEROUS_CAPS]
    if bad:
        f.append(mk(rule("K8S-004"), file, kind, ns, name, cname,
                    f"capabilities.add: {added}",
                    "drop: [ALL], add: [NET_BIND_SERVICE] (only what you need)"))
    if "ALL" not in dropped:
        f.append(mk(rule("K8S-005"), file, kind, ns, name, cname,
                    f"capabilities.drop={dropped}",
                    "capabilities: { drop: [ALL] }"))
    if sc.get("readOnlyRootFilesystem") is not True:
        f.append(mk(rule("K8S-006"), file, kind, ns, name, cname,
                    f"readOnlyRootFilesystem={sc.get('readOnlyRootFilesystem','unset')}",
                    "readOnlyRootFilesystem: true"))
    # Image checks
    if not image or image.endswith(":latest") or ":" not in image.split("/")[-1]:
        f.append(mk(rule("K8S-008"), file, kind, ns, name, cname,
                    f"image='{image}'",
                    "image: myorg/myapp:1.2.3 or @sha256:<digest>"))
    if image and not any(image.startswith(h) or ("/" in image and h.rstrip("/") in image)
                         for h in TRUSTED_REGISTRY_HINTS):
        if "/" in image and not image.startswith("library/"):
            f.append(mk(rule("K8S-015"), file, kind, ns, name, cname,
                        f"image registry not in trusted list: '{image}'",
                        "Use quay.io / ghcr.io / private registry"))
    # Resource limits
    res = c.get("resources") or {}
    limits = res.get("limits") or {}
    if "cpu" not in limits or "memory" not in limits:
        f.append(mk(rule("K8S-009"), file, kind, ns, name, cname,
                    f"resources.limits={limits}",
                    "resources: { limits: { cpu: '500m', memory: '256Mi' } }"))
    # Probes
    if not c.get("livenessProbe") and not c.get("readinessProbe"):
        f.append(mk(rule("K8S-013"), file, kind, ns, name, cname,
                    "no liveness or readiness probe",
                    "livenessProbe: { httpGet: { path: /health, port: 8080 } }"))
    # Secrets via env
    for env in (c.get("env") or []):
        if (env.get("valueFrom") or {}).get("secretKeyRef"):
            f.append(mk(rule("K8S-011"), file, kind, ns, name, cname,
                        f"env {env.get('name')} from secretKeyRef",
                        "Mount secrets as files via volumes instead."))
    return f


def scan_file(path: Path) -> List[Finding]:
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as e:
        print(f"[!] Cannot read {path}: {e}", file=sys.stderr)
        return []
    try:
        docs = load_yaml(text)
    except Exception as e:
        print(f"[!] YAML parse error in {path}: {e}", file=sys.stderr)
        return []
    findings: List[Finding] = []
    for d in docs:
        if not isinstance(d, dict):
            continue
        findings.extend(check_pod(d, str(path)))
    return findings


def scan_target(target: Path) -> List[Finding]:
    findings: List[Finding] = []
    if target.is_file():
        return scan_file(target)
    for p in list(target.rglob("*.yaml")) + list(target.rglob("*.yml")):
        findings.extend(scan_file(p))
    return findings


def build_summary(findings: List[Finding]) -> dict:
    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return {
        "tool": "Kubernetes Admission Controller",
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "by_severity": by_sev,
    }


def print_report(summary, findings):
    print("=" * 60)
    print("  Kubernetes Admission Controller v1.0")
    print("=" * 60)
    print(f"[*] Total findings: {summary['total_findings']}")
    print(f"[*] Breakdown     : {summary['by_severity']}")
    print()
    for f in sorted(findings, key=lambda x: -x.risk_score)[:20]:
        print(f"[{f.severity}] {f.name}")
        print(f"   {f.file} {f.kind}/{f.resource_name} container={f.container} (risk={f.risk_score}, {f.cis})")
        print(f"   > {f.evidence}")
        print()


def main():
    ap = argparse.ArgumentParser(description="Kubernetes Admission Controller (Policy-as-Code)")
    ap.add_argument("target", nargs="?", help="Manifest file or directory")
    ap.add_argument("-o", "--output", default="reports/k8s_report.json")
    ap.add_argument("--html", default="reports/k8s_report.html")
    ap.add_argument("--serve", action="store_true",
                    help="Run as validating admission webhook (requires Flask)")
    ap.add_argument("--port", type=int, default=8443)
    args = ap.parse_args()

    if args.serve:
        serve_webhook(args.port)
        return
    if not args.target:
        ap.error("Provide a target path or use --serve")

    target = Path(args.target)
    if not target.exists():
        print(f"[x] Path not found: {target}", file=sys.stderr)
        sys.exit(1)

    findings = scan_target(target)
    summary = build_summary(findings)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump({"summary": summary, "findings": [asdict(f) for f in findings]}, fh, indent=2)

    generate_html(summary, findings, args.html)
    print_report(summary, findings)
    print(f"[*] JSON report: {args.output}")
    print(f"[*] HTML report: {args.html}")


def serve_webhook(port: int):
    try:
        from flask import Flask, request, jsonify
    except ImportError:
        print("[x] Flask not installed. pip install flask", file=sys.stderr)
        sys.exit(1)

    app = Flask(__name__)

    @app.route("/validate", methods=["POST"])
    def validate():
        review = request.json or {}
        req = review.get("request", {}) or {}
        obj = req.get("object") or {}
        findings = check_pod(obj, file="<admission>") or []
        critical = [f for f in findings if f.severity == "CRITICAL"]
        allowed = len(critical) == 0
        msg = (
            "Admission denied: " + "; ".join(f.name for f in critical)
            if critical else "OK"
        )
        return jsonify({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": req.get("uid", ""),
                "allowed": allowed,
                "status": {"message": msg},
            },
        })

    print(f"[*] Admission webhook listening on :{port}/validate")
    app.run(host="0.0.0.0", port=port)


if __name__ == "__main__":
    try:
        from license_guard import verify_license
        verify_license()
    except Exception:
        pass
    main()
