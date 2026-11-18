# Recipe: Vanity Import URL Resolution

> **Use Case ID:** `BOM-UC-02`  
> **Target Audience:** Go Developers, Package Ecosystem Analysts  
> **Platform Engine:** HTML Meta Tag / Git Redirect Resolver  

---

## 1. Problem Statement

Go modules and other package ecosystems routinely use custom vanity domain names (e.g. `go.uber.org/zap`, `gopkg.in/yaml.v3`, `cloud.google.com/go`). Standard SBOM tools fail to find the underlying Git repository or LICENSE file because the domain does not host raw source code, resulting in blank license notices in generated compliance documents.

---

## 2. When to Use This

Use **Bomhound Vanity URL Resolution** whenever auditing Go or multi-ecosystem codebases. Bomhound parses `go-import` HTML `<meta>` tags and git redirection headers to trace vanity URLs back to their canonical upstream Git repositories (e.g. `github.com/uber-go/zap`).

---

## 3. Architecture & Dataflow

```mermaid
flowchart LR
    Vanity["Vanity Package Path: 'go.uber.org/zap'"] --> Resolver["Bomhound Vanity Resolver"]
    
    Resolver --> Fetch["Fetch https://go.uber.org/zap?go-get=1"]
    Fetch --> Parse["Extract &lt;meta name='go-import'&gt; tag"]
    
    Parse --> Canonical["Canonical Git Repo: 'github.com/uber-go/zap'"]
    Canonical --> License["Extract LICENSE & Copyright from canonical repo"]
```

---

## 4. Prerequisites

1. **Bomhound CLI:** Available on `$PATH`.

---

## 5. Step-by-Step Recipe

### Step 1: Configure Custom Vanity Overrides (Optional)
In `.bomhound.yaml`:
```yaml
resolvers:
  overrides:
    "go.uber.org/*": "github.com/uber-go/*"
    "gopkg.in/yaml.v3": "github.com/go-yaml/yaml"
```

### Step 2: Run Enrichment
```bash
bomhound --input bom.json --output enriched-bom.json
```
Bomhound automatically traces all vanity URLs and reports the resolved upstream Git URLs.

---

## 6. Verification & Expected Output

Inspect resolved components:
```text
[bomhound] Resolved vanity URL 'go.uber.org/zap' -> 'https://github.com/uber-go/zap'
[bomhound] Ingested MIT license text and Uber Technologies copyright notice.
```

---

## 7. Security Invariants & Blast Radius

- **DNS Rebinding Protection:** Ensures redirect URLs do not point to localhost or private IP addresses.

---

## 8. Troubleshooting & Common Pitfalls

- **Issue:** Offline build fails to resolve an obscure vanity URL.  
  **Remediation:** Add a static mapping in `.bomhound.yaml` under `resolvers.static`.
