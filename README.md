# AKS-Security-Ops-Lab-Readme

---
# Create a Sentinel starter pack with a minimal workbook JSON, analytic rule KQLs, and a RUNBOOK.md.
import os, zipfile, textwrap, json, pathlib

base = "/mnt/data/aks-azure-only-sentinel-pack"
obs = os.path.join(base, "observability")
sentinel_dir = os.path.join(base, "sentinel", "analytics")
docs = os.path.join(base, "docs")
os.makedirs(obs, exist_ok=True)
os.makedirs(sentinel_dir, exist_ok=True)
os.makedirs(docs, exist_ok=True)

# Minimal Workbook JSON (focused on AKS signals commonly available via Container Insights)
workbook = {
  "version": "Notebook/1.0",
  "items": [
    {
      "type": 9,
      "content": {
        "version": "KqlItem/1.0",
        "query": textwrap.dedent("""
        // Cluster node health (last 1h)
        InsightsMetrics
        | where TimeGenerated > ago(1h)
        | where Namespace == "container.azm.ms"
        | where Name in ("cpuUsageNanoCores", "memRssBytes")
        | summarize avgCPU=avg(Val/1000000000.0), avgMemMB=avg(Val/1024.0/1024.0) by Computer
        | order by avgCPU desc
        """),
        "size": 1,
        "exportToExcelOptions": "visible",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "gridSettings": {"formatters": [], "labelSettings": []},
        "title": "AKS Node CPU & Memory (avg last 1h)"
      },
      "name": "nodes_cpu_mem",
      "styleSettings": {"height": 300}
    },
    {
      "type": 9,
      "content": {
        "version": "KqlItem/1.0",
        "query": textwrap.dedent("""
        // Pod restarts by namespace (last 1h)
        KubePodInventory
        | where TimeGenerated > ago(1h)
        | summarize Restarts=sum(tolong(RestartCount)) by Namespace
        | order by Restarts desc
        """),
        "size": 1,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "title": "Pod Restarts by Namespace (1h)"
      },
      "name": "pod_restarts",
      "styleSettings": {"height": 280}
    },
    {
      "type": 9,
      "content": {
        "version": "KqlItem/1.0",
        "query": textwrap.dedent("""
        // Suspected 'exec into pod' events (kube-audit) last 24h
        // Adjust the table if your kube-audit data lands elsewhere.
        AzureDiagnostics
        | where TimeGenerated > ago(24h)
        | where Category == "kube-audit"
        | where tostring(RequestURI) has "/exec"
        | project TimeGenerated, Verb, RequestURI, UserAgent_s, SourceSystem, log_s
        | order by TimeGenerated desc
        """),
        "size": 1,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "title": "Kube-audit: Pod Exec Events (24h)"
      },
      "name": "exec_events",
      "styleSettings": {"height": 320}
    },
    {
      "type": 9,
      "content": {
        "version": "KqlItem/1.0",
        "query": textwrap.dedent("""
        // Image pulls from non-ACR registries (last 24h)
        let AllowedRegistry = "youracr.azurecr.io";
        KubePodInventory
        | where TimeGenerated > ago(24h)
        | where isnotempty(Image)
        | extend Img=tostring(Image)
        | where not(Img startswith AllowedRegistry)
        | summarize count() by Img, Namespace
        | order by count_ desc
        """),
        "size": 1,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "title": "Non-ACR Images Observed (24h)"
      },
      "name": "non_acr_images",
      "styleSettings": {"height": 280}
    }
  ],
  "styleSettings": {
    "title": "AKS Security & Ops — Starter Workbook",
    "subtitle": "Health, Restarts, Exec attempts, Registry drift"
  }
}

with open(os.path.join(obs, "aks-secops-starter-workbook.json"), "w", encoding="utf-8") as f:
    json.dump(workbook, f, indent=2)

# Analytic rule KQLs
kql_exec = textwrap.dedent("""
/*
Title: Suspicious Pod Exec (kubectl exec/attach)
Description: Flags kube-audit events indicating interactive access into pods
Schedule: 5 minutes
Query Period: 1 hour
Tactics: Execution, Discovery
*/
AzureDiagnostics
| where TimeGenerated > ago(1h)
| where Category == "kube-audit"
| where tostring(RequestURI) has "/exec" or tostring(RequestURI) has "/attach"
| project TimeGenerated, Resource, RequestURI, Verb, UserAgent_s, log_s
""")

kql_nonacr = textwrap.dedent("""
/*
Title: Image Pulled from Non-Approved Registry
Description: Detects images that are not from your approved ACR
Set parameter AllowedRegistry to your ACR FQDN (e.g., youracr.azurecr.io)
*/
let AllowedRegistry = "youracr.azurecr.io";
KubePodInventory
| where TimeGenerated > ago(1h)
| where isnotempty(Image)
| extend Img=tostring(Image)
| where not(Img startswith AllowedRegistry)
| summarize by TimeGenerated, Namespace, Name, Img
""")

kql_defaultsa = textwrap.dedent("""
/*
Title: Default ServiceAccount Used in Non-system Namespace
Description: Identifies workloads using the default SA outside kube-system
*/
KubePodInventory
| where TimeGenerated > ago(1h)
| where Namespace !in ("kube-system","gatekeeper-system","azure-arc")
| where ServiceAccount == "default"
| summarize Pods=dcount(Name) by Namespace
| order by Pods desc
""")

with open(os.path.join(sentinel_dir, "pod_exec_suspicious.kql"), "w", encoding="utf-8") as f:
    f.write(kql_exec)
with open(os.path.join(sentinel_dir, "image_non_acr.kql"), "w", encoding="utf-8") as f:
    f.write(kql_nonacr)
with open(os.path.join(sentinel_dir, "default_sa_usage.kql"), "w", encoding="utf-8") as f:
    f.write(kql_defaultsa)

# RUNBOOK.md
runbook = r"""# RUNBOOK — AKS Security & Ops (Starter)

This runbook helps you **prove** your lab works and capture screenshots for your README/demo.

## 1) Health & baseline
1. `kubectl get nodes -o wide` — confirm **3 Ready** nodes.
2. `kubectl -n demo get deploy,po,svc` — see `web` with **2 replicas** and a `LoadBalancer` external IP.
3. Browser: hit the external IP; take a screenshot.

## 2) Azure Monitor / Container Insights
1. Azure Portal → **Monitor** → **Containers** → select your cluster.
2. Screenshot the **Cluster** overview (CPU/mem), and **Nodes** tab.

## 3) Sentinel (optional)
1. Portal → **Microsoft Sentinel** → add your LA workspace if not already.
2. Import the workbook JSON:
   - Sentinel → **Workbooks** → **Add workbook** → **Advanced editor** → paste from `observability/aks-secops-starter-workbook.json`.
   - Save as "AKS Security & Ops — Starter".
3. Open the workbook and screenshot the tiles.

## 4) Trigger the detections (for your analytics KQL)
> These are harmless test actions. Perform in the `demo` namespace.

### A) Pod exec attempt
```bash
# exec into a pod (you'll see a kube-audit event if audit logs are flowing)
POD=$(kubectl -n demo get po -l app=web -o jsonpath='{.items[0].metadata.name}')
kubectl -n demo exec -it $POD -- sh -c 'echo hello-from-exec && sleep 1'
```
- In Sentinel Logs, run `pod_exec_suspicious.kql` query (paste KQL from `sentinel/analytics/pod_exec_suspicious.kql`).

B) Pull a non-ACR image (registry drift)
```bash
kubectl -n demo run drift --image=nginx:alpine --restart=Never --command -- sleep 60
kubectl -n demo delete po drift --now
```
- Run `image_non_acr.kql`. Replace `AllowedRegistry` with your ACR FQDN if needed.

C) Default ServiceAccount usage
```bash
# create a simple pod without a dedicated SA (uses default)
kubectl -n demo run sa-check --image=busybox --restart=Never -- sleep 10
```
- Run `default_sa_usage.kql` to see counts by namespace.

5) Optional guardrails (document later)
- Enable Defender for Containers and assign Azure Policy (deny privileged, allow only ACR).
- Capture the Policy compliance and Defender blades as proof.

6) Clean up (optional)
- `kubectl -n demo delete all --all`
- `az group delete -n rg-aks-homelab --yes`
"""

with open(os.path.join(docs, "RUNBOOK.md"), "w", encoding="utf-8") as f:
f.write(runbook)

Zip pack

zip_path = "/mnt/data/aks-azure-only-sentinel-pack.zip"
with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
for folder, _, files in os.walk(base):
for file in files:
full = os.path.join(folder, file)
rel = os.path.relpath(full, base)
z.write(full, arcname=os.path.join("aks-azure-only-sentinel-pack", rel))

```zip_path
Result
'/mnt/data/aks-azure-only-sentinel-pack.zip'
```
Awesome — I added a Sentinel starter pack with a minimal workbook, three analytic rule KQLs, and a guided RUNBOOK to trigger/test detections.
- [Download the Sentinel Pack]

What you get:
```pearl
aks-azure-only-sentinel-pack/
├─ observability/
│  └─ aks-secops-starter-workbook.json   # import via Sentinel → Workbooks → Advanced editor
├─ sentinel/
│  └─ analytics/
│     ├─ pod_exec_suspicious.kql         # kube-audit: /exec or /attach
│     ├─ image_non_acr.kql               # registry drift (not from your ACR)
│     └─ default_sa_usage.kql            # default SA used outside system namespaces
└─ docs/
   └─ RUNBOOK.md                         # screenshots + how to trigger alerts
```
How to plug this into what you already downloaded:
1. Keep using the AKS Azure-only starter you grabbed earlier.
2. Drop these folders into the same repo (e.g., observability/, sentinel/, docs/).
3. In Sentinel, import the workbook JSON, then run the KQL files from the sentinel/analytics folder after you trigger the test actions in RUNBOOK.md.

Want me to also generate:
- a policy-as-code starter (deny privileged pods / allow only ACR),
- and a Defender for Containers verification checklist (screens you should capture)?


---

---

# Retry creating README.md and the cleaned Python script, then zip them.

import os, textwrap, zipfile

base = "/mnt/data/aks-azure-readme-and-script"
os.makedirs(base, exist_ok=True)

readme = textwrap.dedent("""
# AKS Security & Ops Lab — Azure-Only

This repo shows how to spin up a small **3-node Azure Kubernetes Service (AKS)** cluster, deploy a sample app, turn on monitoring, and (optionally) add security guardrails. It’s written for **both non-technical readers** and **engineers**—so you’ll see plain-English explanations and copy-paste code blocks.

---

## What you’ll get (in plain English)

- A **secure, small AKS cluster** (3 virtual machines) running a demo website.
- A **monitoring dashboard** so you can see CPU/memory and pod restarts.
- Optional security add-ons:
  - **Policies** that block risky containers and allow only your private registry (ACR).
  - **Autoscaling** so the website can grow from 2 to 6 copies if CPU gets busy.
  - **(Optional)** Azure Defender and GitHub Actions notes.

If you can copy and paste, you can get this running.

---

## Quick Start (copy-paste)

> **Tools:** Azure CLI, kubectl. Shell examples use **PowerShell** on Windows; Bash works too with minor syntax changes.

### 1) Set your names (you can keep the defaults)
```powershell
$RG       = "rg-aks-homelab"
$LOC      = "eastus"
$CLUSTER  = "aks-homelab"
$NODECNT  = 3
$SIZE     = "Standard_B2s"
$LA       = "la-aks-homelab"
$ACR      = "youruniqueacr1234"   # must be globally unique, lowercase
```

2) Create Resource Group, Log Analytics, and ACR
```powershell
az group create --name $RG --location $LOC
az monitor log-analytics workspace create -g $RG -n $LA
az acr create -g $RG -n $ACR --sku Basic
```

3) Create the AKS cluster (3 nodes) and connect
```powershell
az aks create `
  --resource-group $RG `
  --name $CLUSTER `
  --node-count $NODECNT `
  --node-vm-size $SIZE `
  --enable-addons monitoring `
  --generate-ssh-keys

az aks get-credentials --resource-group $RG --name $CLUSTER
kubectl get nodes -o wide

```
The “monitoring” add-on connects your cluster to Azure Monitor so you can see health charts without extra setup.

4) Deploy the demo app
```powershell
kubectl create ns demo
kubectl -n demo apply -f manifests/deployment.yaml
kubectl -n demo apply -f manifests/service-lb.yaml
kubectl -n demo get svc web -o wide   # copy the External IP and open it in a browser
```
You now have a site running on AKS. 🎉 Take a screenshot of the page and the kubectl get nodes output for your portfolio.



## Optional: Security & Scaling Add-Ons
You can add these any time:

A) Horizontal Pod Autoscaler (HPA)
```powershell
kubectl -n demo apply -f manifests/hpa-web.yaml
```
This lets the web deployment scale from 2 → 6 replicas when CPU usage rises above 60%.

B) Policies (deny risky containers; allow only ACR)
```powershell
# Edit scripts/assign-policies.ps1 to set your ACR FQDN (e.g., youracr.azurecr.io)
.\scripts\assign-policies.ps1
```
This applies two guardrails at the subscription level:
- Deny privileged containers (blocks pods that try to run with dangerous privileges)
- Allow only ACR (prevents pulling images from random public registries)

C) (Optional) Ingress + TLS template
```powershell
# After you install NGINX Ingress + cert-manager, edit manifests/ingress-tls.yaml with your domain
kubectl -n demo apply -f manifests/ingress-tls.yaml
```

Monitoring & (Optional) Sentinel
- Azure Monitor / Container Insights is already on from step 3. In Azure Portal → Monitor → Containers, select your cluster to see CPU/mem charts.
- If you want a SIEM view, add Microsoft Sentinel on your Log Analytics workspace and import the starter workbook (JSON provided in the Sentinel pack).

Repo Layout (recommended)
```bash
infra/            # scripts to create/destroy the lab (PowerShell or Bash)
manifests/        # Kubernetes YAML (deployment, service, hpa, ingress)
observability/    # optional workbooks or dashboards
sentinel/         # optional KQL rules
docs/             # quickstarts, runbooks, screenshots
scripts/          # policy assignments and helpers
```

Clean Up
```powershell
az group delete --name $RG --yes --no-wait
```
This deletes everything you created to avoid charges.





















---
