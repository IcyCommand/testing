# Prompt for the local admin credentials
$adminUsername = "Administrator"
$securePassword = Read-Host -Prompt "Enter password for $adminUsername" -AsSecureString
$credential = New-Object System.Management.Automation.PSCredential($adminUsername, $securePassword)

# Start a new PowerShell process with the provided admin credentials
Start-Process powershell.exe -Credential $credential -ArgumentList '-NoExit -Command "Start-Process PowerShell -Verb RunAs"'
