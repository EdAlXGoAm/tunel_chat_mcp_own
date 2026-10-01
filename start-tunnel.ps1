param(
    [switch]$NonInteractive,
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
foreach ($value in @($dataRoot, $ClientPath)) {
    if ($value -and $value -match '[\r\n"]') { throw "Las rutas no pueden contener caracteres de control ni comillas." }
}

foreach ($requiredPath in @($ClientPath, $cliPath, $nodePath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Falta un archivo necesario: $requiredPath"
    }
}

$arguments = @($cliPath, "run", "--data-root", $dataRoot, "--client", $ClientPath)
if ($NonInteractive) { $arguments += "--non-interactive" }
if (-not [string]::IsNullOrWhiteSpace($Profile)) { $arguments += @("--profile", $Profile) }
if (-not [string]::IsNullOrWhiteSpace($HealthListenAddr)) { $arguments += @("--health-listen-addr", $HealthListenAddr) }
if (-not [string]::IsNullOrWhiteSpace($PanelPort)) { $arguments += @("--panel-port", $PanelPort) }
& $nodePath @arguments
exit $LASTEXITCODE
