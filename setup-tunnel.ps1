param(
    [string]$TunnelId,
    [string]$Workspace,
    [string]$ClientPath,
    [string]$DataRoot,
    [string]$Profile,
    [string]$HealthListenAddr,
    [string]$PanelPort
)

$ErrorActionPreference = "Stop"

$baseDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$cliPath = Join-Path $baseDirectory "cli.mjs"
$dataRoot = if ($DataRoot) { $DataRoot } elseif ($env:MCP_TUNNEL_DATA_ROOT) { $env:MCP_TUNNEL_DATA_ROOT } else { Join-Path $env:LOCALAPPDATA "OpenAI-Secure-MCP-Tunnel" }
$connectionPath = Join-Path $dataRoot "tunnel.json"
$workspaceConfigPath = Join-Path $dataRoot "workspace.json"
$nodePath = (Get-Command node -ErrorAction Stop).Source

if ([string]::IsNullOrWhiteSpace($ClientPath)) {
    $ClientPath = Join-Path $baseDirectory "vendor\tunnel-client\tunnel-client.exe"
}
if ([string]::IsNullOrWhiteSpace($Profile) -and $env:MCP_TUNNEL_CLIENT_PROFILE) {
    $Profile = $env:MCP_TUNNEL_CLIENT_PROFILE
}
if ([string]::IsNullOrWhiteSpace($HealthListenAddr) -and $env:MCP_TUNNEL_HEALTH_LISTEN_ADDR) {
    $HealthListenAddr = $env:MCP_TUNNEL_HEALTH_LISTEN_ADDR
}
if ([string]::IsNullOrWhiteSpace($PanelPort) -and $env:CONTROL_PANEL_PORT) {
    $PanelPort = $env:CONTROL_PANEL_PORT
}
foreach ($requiredPath in @($ClientPath, $cliPath, $nodePath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Falta un archivo necesario: $requiredPath"
    }
}

if ([string]::IsNullOrWhiteSpace($TunnelId) -and (Test-Path -LiteralPath $connectionPath -PathType Leaf)) {
    $TunnelId = [string](Get-Content -Raw -LiteralPath $connectionPath | ConvertFrom-Json).tunnelId
}
if ([string]::IsNullOrWhiteSpace($TunnelId)) {
    $TunnelId = Read-Host "Identificador del tunel de OpenAI (tunnel_...)"
}
if ($TunnelId -notmatch '^tunnel_[a-z0-9]{32}$') {
    throw "El identificador del tunel debe usar tunnel_ seguido de 32 caracteres minusculos o digitos."
}

if ([string]::IsNullOrWhiteSpace($Workspace) -and (Test-Path -LiteralPath $workspaceConfigPath -PathType Leaf)) {
    $Workspace = [string](Get-Content -Raw -LiteralPath $workspaceConfigPath | ConvertFrom-Json).workspaceRoot
}
if ([string]::IsNullOrWhiteSpace($Workspace)) {
    $Workspace = Read-Host "Ruta de la carpeta de trabajo autorizada"
}

$arguments = @(
    $cliPath, "setup",
    "--workspace", $Workspace,
    "--tunnel-id", $TunnelId,
    "--client", $ClientPath,
    "--data-root", $dataRoot
)
if (-not [string]::IsNullOrWhiteSpace($Profile)) { $arguments += @("--profile", $Profile) }
if (-not [string]::IsNullOrWhiteSpace($HealthListenAddr)) { $arguments += @("--health-listen-addr", $HealthListenAddr) }
if (-not [string]::IsNullOrWhiteSpace($PanelPort)) { $arguments += @("--panel-port", $PanelPort) }

& $nodePath @arguments

if ($LASTEXITCODE -ne 0) {
    throw "La configuracion del tunel termino con codigo $LASTEXITCODE."
}
