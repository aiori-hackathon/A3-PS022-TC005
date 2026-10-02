# Creates the segfault-target and segfault-gen VirtualBox VMs (NAT + virtio-net on internal network "segfault-lab").
param(
    [Parameter(Mandatory = $true)][string]$Iso,
    [string]$BaseDir = (Join-Path $env:USERPROFILE "VirtualBox VMs"),
    [int]$Cpus = 2,
    [int]$MemoryMb = 2048,
    [int]$DiskGb = 25,
    [string]$User = "segfault",
    [string]$Password = "segfault",
    [switch]$Unattended
)

$ErrorActionPreference = "Stop"
$vbox = Join-Path $env:ProgramFiles "Oracle\VirtualBox\VBoxManage.exe"
if (-not (Test-Path $vbox)) { throw "VBoxManage not found at $vbox" }
if (-not (Test-Path $Iso)) { throw "ISO not found: $Iso" }

# Runs VBoxManage and stops on a non-zero exit code.
function Invoke-VBox {
    & $vbox @args
    if ($LASTEXITCODE -ne 0) { throw "VBoxManage $($args -join ' ') failed ($LASTEXITCODE)" }
}

$existing = & $vbox list vms
foreach ($name in @("segfault-target", "segfault-gen")) {
    if ($existing -match "`"$name`"") { Write-Host "$name already exists, skipping"; continue }
    Write-Host "==> creating $name"
    Invoke-VBox createvm --name $name --ostype Ubuntu_64 --register --basefolder $BaseDir
    Invoke-VBox modifyvm $name --cpus $Cpus --memory $MemoryMb --vram 16 --graphicscontroller vmsvga --ioapic on
    Invoke-VBox modifyvm $name --nic1 nat --nictype1 virtio --nic2 intnet --intnet2 segfault-lab --nictype2 virtio
    $disk = Join-Path $BaseDir "$name\$name.vdi"
    Invoke-VBox createmedium disk --filename $disk --size ($DiskGb * 1024) --format VDI
    Invoke-VBox storagectl $name --name SATA --add sata --controller IntelAhci --portcount 2
    Invoke-VBox storageattach $name --storagectl SATA --port 0 --device 0 --type hdd --medium $disk
    if ($Unattended) {
        Invoke-VBox unattended install $name --iso=$Iso --user=$User --password=$Password --full-user-name=$User --hostname="$name.lab" --start-vm=gui
    } else {
        Invoke-VBox storageattach $name --storagectl SATA --port 1 --device 0 --type dvddrive --medium $Iso
        Invoke-VBox startvm $name --type gui
    }
}
Write-Host "done: finish the Ubuntu install in each VM, then follow docs/lab-setup.md"
