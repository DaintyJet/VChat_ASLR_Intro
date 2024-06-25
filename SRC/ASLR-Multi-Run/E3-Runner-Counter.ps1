
$start = 0
$limit = 1000

'' | Out-File -FilePath .\Result.txt
for (; $start -lt $limit; $start++)
{
    &".\x64\Debug\ASLR-Multi-Run.exe" | Out-File -Append -FilePath .\Result.txt
}

# Read the contents of the file
$lines = Get-Content -Path "Result.txt"

$num_lines = ($lines | Measure-Object -Line).Lines

# Sort the lines and select unique lines
$uniqueLines = $lines | Where-Object { $_ -ne "" } | Sort-Object  | Select-Object -Unique

$num_uniq_lines = ($uniqueLines | Measure-Object -Line).Lines 

# Output the unique lines
Write-Output "UNIQUE Addresses:"
$uniqueLines

Write-Output "`nRESULTS"
Write-Output ("We have {0} original addresses and {1} which appears only once" -f $num_lines, $num_uniq_lines)
