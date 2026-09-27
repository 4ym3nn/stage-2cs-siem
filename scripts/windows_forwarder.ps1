param(
  [string]$SiemUrl = "http://127.0.0.1:8000",
  [string]$ApiKey = $env:SIEM_INGEST_API_KEY,
  [int]$PollSeconds = 5
)

$ErrorActionPreference = "Stop"
if (-not $ApiKey) { $ApiKey = $env:SIEM_API_KEY }
$headers = @{ "Content-Type" = "application/json" }
if ($ApiKey) { $headers["X-API-Key"] = $ApiKey }
$ids = 1102,4624,4625,4688,4720,4732
$lastRecordId = 0

Write-Host "Forwarding Windows Security events to $SiemUrl"
Write-Host "Event IDs: $($ids -join ', ')"

while ($true) {
  try {
    $events = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=$ids } -MaxEvents 100 |
      Where-Object { $_.RecordId -gt $lastRecordId } |
      Sort-Object RecordId

    foreach ($e in $events) {
      $xml = [xml]$e.ToXml()
      $data = @{}
      foreach ($d in $xml.Event.EventData.Data) {
        if ($d.Name) { $data[$d.Name] = [string]$d.'#text' }
      }

      $payload = @{
        timestamp      = $e.TimeCreated.ToUniversalTime().ToString("o")
        Computer       = $e.MachineName
        EventID        = $e.Id
        TargetUserName = $data['TargetUserName']
        IpAddress      = $data['IpAddress']
        message        = $e.Message
      } | ConvertTo-Json -Depth 5

      Invoke-RestMethod -Method Post -Uri "$SiemUrl/api/ingest/windows" -Headers $headers -Body $payload | Out-Null
      if ($e.RecordId -gt $lastRecordId) { $lastRecordId = $e.RecordId }
    }
  } catch {
    Write-Warning $_.Exception.Message
  }
  Start-Sleep -Seconds $PollSeconds
}
