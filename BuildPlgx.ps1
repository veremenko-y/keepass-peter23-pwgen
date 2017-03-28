$Path = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
$Path = [System.IO.Path]::Combine($Path, "src");

$Exec = ".\tools\KeePass.exe --plgx-create $Path --plgx-prereq-net:4"

Remove-Item ".\release" -Recurse -Force 
New-Item ".\release" -ItemType:Directory | Out-Null

Invoke-Expression $Exec

Rename-Item "src.plgx" -NewName "YvPwGenPeter23.plgx"

Move-Item "YvPwGenPeter23.plgx" "release\YvPwGenPeter23.plgx"
