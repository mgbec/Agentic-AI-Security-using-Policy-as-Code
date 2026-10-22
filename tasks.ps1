<#
.SYNOPSIS
  PowerShell task runner for the OWASP Agentic AI (ASI) policy-as-code repo.
  Windows-friendly equivalent of the Makefile.

.EXAMPLE
  ./tasks.ps1 install
  ./tasks.ps1 all
  ./tasks.ps1 opa
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('help', 'install', 'all', 'schema', 'opa', 'semgrep',
        'checkov', 'tf', 'clean')]
    [string]$Task = 'help'
)

$ErrorActionPreference = 'Stop'
$TfDir = 'terraform'

function Invoke-Step($name, $script) {
    Write-Host "==> $name" -ForegroundColor Cyan
    & $script
    if ($LASTEXITCODE -ne 0) { throw "$name failed (exit $LASTEXITCODE)" }
}

function Install-Binaries {
    $binaries = @('terraform', 'conftest', 'gitleaks')
    $choco = Get-Command choco -ErrorAction SilentlyContinue
    if (-not $choco) {
        Write-Host "`nChocolatey not found; install these manually:" -ForegroundColor Yellow
        Write-Host "  terraform -> https://developer.hashicorp.com/terraform/install"
        Write-Host "  conftest  -> https://www.conftest.dev/install/"
        Write-Host "  gitleaks  -> https://github.com/gitleaks/gitleaks#installing"
        return
    }
    foreach ($b in $binaries) {
        if (Get-Command $b -ErrorAction SilentlyContinue) {
            Write-Host "  $b already installed - skipping" -ForegroundColor DarkGray
            continue
        }
        Write-Host "==> choco install $b" -ForegroundColor Cyan
        choco install $b -y
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  choco install $b failed (are you in an elevated shell?)" -ForegroundColor Yellow
        }
    }
}

function Task-Help {
    Write-Host "Usage: ./tasks.ps1 <task>`n"
    @(
        @('install', 'Install Python tools + binaries (choco on Windows)'),
        @('all', 'Run every check (schema, opa, semgrep, checkov, tf)'),
        @('schema', 'Validate agent manifests against JSON Schemas (ASI01/02/04/06/07)'),
        @('opa', 'Conftest on agent configs + supply chain (ASI01/02/04/06/07/09/10)'),
        @('semgrep', 'Agent-code SAST (ASI05/ASI06/ASI02)'),
        @('checkov', 'Terraform scan + custom ASI policies (ASI03)'),
        @('tf', 'Terraform fmt/validate + Conftest on the plan (ASI03/08/10)'),
        @('clean', 'Remove Terraform working files')
    ) | ForEach-Object { "  {0,-10} {1}" -f $_[0], $_[1] }
}

function Task-Install {
    Invoke-Step 'pip install' { pip install -r requirements.txt }
    Invoke-Step 'pre-commit install' { pre-commit install }
    Install-Binaries
}

function Task-Schema {
    Invoke-Step 'schema: agent' { check-jsonschema --schemafile schemas/agent.schema.json agents/summarizer.agent.yaml }
    Invoke-Step 'schema: tools' { check-jsonschema --schemafile schemas/tools.schema.json agents/tools/tools.yaml }
    Invoke-Step 'schema: mcp' { check-jsonschema --schemafile schemas/mcp.schema.json agents/mcp/mcp.json }
}

function Task-Opa {
    Invoke-Step 'opa: agent' { conftest test agents/summarizer.agent.yaml --policy policies/opa --namespace agent }
    Invoke-Step 'opa: tools' { conftest test agents/tools/tools.yaml --policy policies/opa --namespace supplychain }
    Invoke-Step 'opa: mcp' { conftest test agents/mcp/mcp.json --policy policies/opa --namespace supplychain }
}

function Task-Semgrep { Invoke-Step 'semgrep' { semgrep scan --config policies/semgrep/agentic.yaml --error src } }
function Task-Checkov { Invoke-Step 'checkov' { checkov -d $TfDir --external-checks-dir policies/checkov --compact } }

function Task-Tf {
    Invoke-Step 'terraform fmt' { terraform -chdir=$TfDir fmt -check -recursive }
    Invoke-Step 'terraform init' { terraform -chdir=$TfDir init -backend=false -input=false }
    Invoke-Step 'terraform validate' { terraform -chdir=$TfDir validate }
    Invoke-Step 'terraform plan' { terraform -chdir=$TfDir plan -out=tfplan.binary -input=false }
    Invoke-Step 'terraform show -json' { terraform -chdir=$TfDir show -json tfplan.binary | Out-File -Encoding utf8 "$TfDir/tfplan.json" }
    Invoke-Step 'conftest plan' { conftest test "$TfDir/tfplan.json" --policy policies/opa --namespace tfplan }
}

function Task-All {
    Task-Schema; Task-Opa; Task-Semgrep; Task-Checkov; Task-Tf
    Write-Host "`nAll checks passed." -ForegroundColor Green
}

function Task-Clean {
    Remove-Item -Recurse -Force "$TfDir/.terraform", "$TfDir/.terraform.lock.hcl" -ErrorAction SilentlyContinue
    Remove-Item -Force "$TfDir/tfplan.binary", "$TfDir/tfplan.json" -ErrorAction SilentlyContinue
    Write-Host "Cleaned Terraform artifacts."
}

switch ($Task) {
    'help' { Task-Help }
    'install' { Task-Install }
    'all' { Task-All }
    'schema' { Task-Schema }
    'opa' { Task-Opa }
    'semgrep' { Task-Semgrep }
    'checkov' { Task-Checkov }
    'tf' { Task-Tf }
    'clean' { Task-Clean }
}
