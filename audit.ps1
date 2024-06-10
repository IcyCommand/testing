<#ToDo
'Administrators' SPN Count doesn't work but others do - fix this
Output actual user lists to a text file or something
#>

Remove-Variable * -ErrorAction SilentlyContinue
$d90 = [DateTime]::Today.AddDays(-90)
$d365 = [DateTime]::Today.AddDays(-365) 
Add-Content -Path $PSScriptRoot"\ADAccountStatistics.csv" -Value '"Statistic","Affected Accounts"'
$outputCSV = ($(Resolve-Path "$($PSScriptRoot)\ADAccountStatistics.csv").ToString())

Write-Host "Script started..." -ForegroundColor Green
Write-Host "---------------" -ForegroundColor Red

#Group Counts
#Enterprise Admins Group Checks
#-----------------------------------------------------
$enterpriseAdmins = (Get-ADGroupMember -Identity 'Enterprise Admins' -Recursive) | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Number of Enterprise Admins: $($enterpriseAdmins.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Enterprise Admins,$($enterpriseAdmins.Count)"
Write-Host "---------------" -ForegroundColor Red

$enterpriseAdminsProtectedCount = 0
$enterpriseAdminsProtectedList = New-Object System.Collections.Generic.List[string]
$enterpriseAdminsDelegatedCount = 0
$enterpriseAdminsDelegatedList = New-Object System.Collections.Generic.List[string]
$disabledEnterpriseAdminCount = 0
$disabledEnterpriseAdminList = New-Object System.Collections.Generic.List[string]
$enterpriseAdminsSPNCount = 0
$enterpriseAdminsSPNList = New-Object System.Collections.Generic.List[string]
foreach($user in $enterpriseAdmins){
    $getUser = Get-ADUser -Identity $user -Properties enabled, AccountNotDelegated, servicePrincipalName
    if($getUser.AccountNotDelegated -eq $false){
        $enterpriseAdminsDelegatedCount += 1
        $enterpriseAdminsDelegatedList.Add($getUser.SamAccountName)
    }
    $protectedUsersCheck = Get-ADGroupMember -Identity 'Protected Users' | Where-Object {$_.name -eq $user}
    if(!$protectedUsersCheck){
        $enterpriseAdminsProtectedCount += 1
        $enterpriseAdminsProtectedList.Add($user)
    }
    if($getUser.Enabled -eq $False){
        $disabledEnterpriseAdminCount += 1
        $disabledEnterpriseAdminList.Add($getUser.SamAccountName)
    }
    if($getUser.servicePrincipalName){
        $enterpriseAdminsSPNCount += 1
        $enterpriseAdminsSPNList.Add($getUser.SamAccountName)
    }
}

Write-Host "Number of Enterprise Admins with Delegation Allowed: $($enterpriseAdminsDelegatedCount)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Enterprise Admins with Delegation Allowed,$($enterpriseAdminsDelegatedCount)"
Write-Host "---------------" -ForegroundColor Red
Write-Host "Number of Enterprise Admins Not in Protected Users Group: $($enterpriseAdminsProtectedCount)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Enterprise Admins Not in Protected Users Group,$($enterpriseAdminsProtectedCount)"
Write-Host "---------------" -ForegroundColor Red
Write-Host "Number of Disabled Accounts in Enterprise Admins Group: $($disabledEnterpriseAdminCount)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Disabled Accounts in Enterprise Admins Group,$($disabledEnterpriseAdminCount)"
Write-Host "---------------" -ForegroundColor Red
Write-Host "Number of Enterprise Admins with SPNs Configured: $($enterpriseAdminsSPNCount)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Enterprise Admins with SPNs Configured,$($enterpriseAdminsSPNCount)"
Write-Host "---------------" -ForegroundColor Red
#-----------------------------------------------------

#Domain Admins Group Checks
#-----------------------------------------------------
$domainAdmins = Get-ADGroupMember -Identity 'Domain Admins' -Recursive | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Number of Domain Admins: $($domainAdmins.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Domain Admins,$($domainAdmins.Count)"
Write-Host "---------------" -ForegroundColor Red

$domainAdminsProtectedCount = 0
$domainAdminsProtectedList = New-Object System.Collections.Generic.List[string]
$domainAdminsDelegatedCount = 0
$domainAdminsDelegatedList = New-Object System.Collections.Generic.List[string]
$disabledDomainAdminCount = 0
$disabledDomainAdminList = New-Object System.Collections.Generic.List[string]
$domainAdminsSPNCount = 0
$domainAdminsSPNList = New-Object System.Collections.Generic.List[string]
foreach($user in $domainAdmins){
    $getUser = Get-ADUser -Identity $user -Properties enabled, AccountNotDelegated, servicePrincipalName
    if($getUser.AccountNotDelegated -eq $false){
        $domainAdminsDelegatedCount += 1
        $domainAdminsDelegatedList.Add($getUser.SamAccountName)
    }
    $protectedUsersCheck = Get-ADGroupMember -Identity 'Protected Users' | Where-Object {$_.name -eq $user}
    if(!$protectedUsersCheck){
        $domainAdminsProtectedCount += 1
        $domainAdminsProtectedList.Add($user)
    }
    if($getUser.Enabled -eq $False){
        $disabledDomainAdminCount += 1
        $disabledDomainAdminList.Add($getUser.SamAccountName)
    }
    if($getUser.servicePrincipalName){
        $domainAdminsSPNCount += 1
        $domainAdminsSPNList.Add($getUser.SamAccountName)
    }
}

Write-Host "Number of Domain Admins with Delegation Allowed: $($domainsAdminsDelegatedCount)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Domain Admins with Delegation Allowed,$($domainsAdminsDelegatedCount)"
Write-Host "---------------" -ForegroundColor Red
Write-Host "Number of Domain Admins Not in Protected Users Group: $($domainAdminsProtectedCount)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Domain Admins Not in Protected Users Group,$($domainAdminsProtectedCount)"
Write-Host "---------------" -ForegroundColor Red
Write-Host "Number of Disabled Accounts in Domain Admins Group: $($disabledDomainAdminCount)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Disabled Accounts in Domain Admins Group,$($disabledDomainAdminCount)"
Write-Host "---------------" -ForegroundColor Red
Write-Host "Number of Domain Admins with SPNs Configured: $($domainAdminsSPNCount)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Domain Admins with SPNs Configured,$($domainAdminsSPNCount)"
Write-Host "---------------" -ForegroundColor Red
#-----------------------------------------------------

#Administrators Group Checks
#-----------------------------------------------------
$administrators = Get-ADGroupMember -Identity 'Administrators' -Recursive | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Number of Administrators: $($administrators.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Administrators,$($administrators.Count)"
Write-Host "---------------" -ForegroundColor Red

$administratorsProtectedCount = 0
$administratorsProtectedList = New-Object System.Collections.Generic.List[string]
$administratorsDelegatedCount = 0
$administratorsDelegatedList = New-Object System.Collections.Generic.List[string]
$disabledAdministratorsCount = 0
$disabledAdministratorsList = New-Object System.Collections.Generic.List[string]
$administratorsSPNCount = 0
$administratorsSPNList = New-Object System.Collections.Generic.List[string]
foreach($user in $administrators){
    $getUser = Get-ADUser -Identity $user -Properties enabled, AccountNotDelegated
    if($getUser.AccountNotDelegated -eq $false){
        $administratorsDelegatedCount += 1
        $administratorsDelegatedList.Add($getUser.SamAccountName)
    }
    $protectedUsersCheck = Get-ADGroupMember -Identity 'Protected Users' | Where-Object {$_.name -eq $user}
    if(!$protectedUsersCheck){
        $administratorsProtectedCount += 1
        $administratorsProtectedList.Add($user)
    }
    if($getUser.Enabled -eq $False){
        $disabledAdministratorsCount += 1
        $disabledAdministratorsList.Add($getUser.SamAccountName)
    }
    if($getUser.servicePrincipalName){
        $administratorsSPNCount += 1
        $administratorsSPNList.Add($getUser.SamAccountName)
    }
}

Write-Host "Number of Administrators with Delegation Allowed: $($administratorsDelegatedCount)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Administrators with Delegation Allowed,$($administratorsDelegatedCount)"
Write-Host "---------------" -ForegroundColor Red
Write-Host "Number of Administrators Not in Protected Users Group: $($administratorsProtectedCount)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Administrators Not in Protected Users Group,$($administratorsProtectedCount)"
Write-Host "---------------" -ForegroundColor Red
Write-Host "Number of Disabled Accounts in Administrators Group: $($disabledAdministratorsCount)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Disabled Accounts in Administrators Group,$($disabledAdministratorsCount)"
Write-Host "---------------" -ForegroundColor Red
Write-Host "Number of Administrators with SPNs Configured: $($administratorsSPNCount)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Administrators with SPNs Configured,$($administratorsSPNCount)"
Write-Host "---------------" -ForegroundColor Red
#-----------------------------------------------------

$schemaAdmins = (Get-ADGroupMember -Identity 'Schema Admins' -Recursive) | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Number of Schema Admins: $($schemaAdmins.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Schema Admins,$($schemaAdmins.Count)"
Write-Host "---------------" -ForegroundColor Red

$accountOperators = (Get-ADGroupMember -Identity 'Account Operators' -Recursive) | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Number of Account Operators: $($accountOperators.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Account Operators,$($accountOperators.Count)"
Write-Host "---------------" -ForegroundColor Red

$keyAdmins = (Get-ADGroupMember -Identity 'Key Admins' -Recursive) | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Number of Key Admins: $($keyAdmins.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Key Admins,$($keyAdmins.Count)"
Write-Host "---------------" -ForegroundColor Red

$enterpriseKeyAdmins = (Get-ADGroupMember -Identity 'Enterprise Key Admins' -Recursive) | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Number of Enterprise Key Admins: $($enterpriseKeyAdmins.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Enterprise Key Admins,$($enterpriseKeyAdmins.Count)"
Write-Host "---------------" -ForegroundColor Red

$backupOperators = (Get-ADGroupMember -Identity 'Backup Operators' -Recursive) | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Number of Backup Operators: $($backupOperators.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Backup Operators,$($backupOperators.Count)"
Write-Host "---------------" -ForegroundColor Red

$gpCreatorOwners = (Get-ADGroupMember -Identity 'Group Policy Creator Owners' -Recursive) | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Number of Group Policy Creator Owners: $($gpCreatorOwners.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Group Policy Creator Owners,$($gpCreatorOwners.Count)"
Write-Host "---------------" -ForegroundColor Red

$forestTrustBuilders = (Get-ADGroupMember -Identity 'Incoming Forest Trust Builders' -Recursive) | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Number of Incoming Forest Trust Builders: $($forestTrustBuilders.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Incoming Forest Trust Builders,$($forestTrustBuilders.Count)"
Write-Host "---------------" -ForegroundColor Red

$printOperators = (Get-ADGroupMember -Identity 'Print Operators' -Recursive) | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Number of Print Operators: $($printOperators.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Print Operators,$($printOperators.Count)"
Write-Host "---------------" -ForegroundColor Red

$networkConfigOperators = (Get-ADGroupMember -Identity 'Network Configuration Operators' -Recursive) | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Number of Network Configuration Operators: $($networkConfigOperators.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Network Configuration Operators,$($networkConfigOperators.Count)"
Write-Host "---------------" -ForegroundColor Red

$replicators = (Get-ADGroupMember -Identity 'Replicator' -Recursive) | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Number of Replicators: $($replicators.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Replicators,$($replicators.Count)"
Write-Host "---------------" -ForegroundColor Red

$serverOperators = (Get-ADGroupMember -Identity 'Server Operators' -Recursive) | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Number of Server Operators: $($serverOperators.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Server Operators,$($serverOperators.Count)"
Write-Host "---------------" -ForegroundColor Red

$dnsAdmins = (Get-ADGroupMember -Identity 'DNSAdmins' -Recursive) | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Number of DNS Admins: $($dnsAdmins.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of DNS Admins,$($dnsAdmins.Count)"
Write-Host "---------------" -ForegroundColor Red
#-----------------------------------------------------

#Configuration Checks
#-----------------------------------------------------
$disabledUsers = Get-ADUser -Filter {(enabled -eq $false)} | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Disabled users: $($disabledUsers.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Disabled users',$($disabledUsers.Count)"
Write-Host "---------------" -ForegroundColor Red

$inactive90Days = Get-ADUser -Filter {(enabled -eq $true) -and (LastLogonTimestamp -le $d90)}  -Properties LastLogonDate | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Enabled users inactive for 90 days: $($inactive90Days.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Enabled Users Inactive for 90 Days',$($inactive90Days.Count)"
Write-Host "---------------" -ForegroundColor Red

$inactive1Year = Get-ADUser -Filter {(enabled -eq $true) -and (LastLogonTimestamp -le $d365)} -Properties LastLogonDate | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Enabled users inactive for 1 year: $($inactive1Year.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Enabled Users Inactive for 1 Year',$($inactive1Year.Count)"
Write-Host "---------------" -ForegroundColor Red

$passNotRequired = Get-ADUser -Filter {(enabled -eq $true) -and (PasswordNotRequired -eq $true)} -Properties PasswordNotRequired | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Enabled users that don't require a password: $($passNotRequired.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Password Not Required',$($passNotRequired.Count)"
Write-Host "---------------" -ForegroundColor Red

$passNeverExpires = Get-ADUser -Filter {(enabled -eq $true) -and (PasswordNeverExpires -eq $true)} -Properties PasswordNeverExpires | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Enabled users with non-expiring passwords: $($passNeverExpires.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Password Never Expires,$($passNeverExpires.Count)"
Write-Host "---------------" -ForegroundColor Red

$passwordUnchangedLastYear = Get-ADUser -Filter {(enabled -eq $true) -and (PasswordLastSet -le $d365)} -Properties PasswordLastSet | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Enabled users who have not changed their password in the last year: $($passwordUnchangedLastYear.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Password Unchanged in Last Year,$($passwordUnchangedLastYear.Count)"
Write-Host "---------------" -ForegroundColor Red

$passwordUnchangedLast90Days = Get-ADUser -Filter {(enabled -eq $true) -and (PasswordLastSet -le $d90)} -Properties PasswordLastSet | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Enabled users who have not changed their password in the last 90 days: $($passwordUnchangedLast90Days.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Password Unchanged in Last 90 Days,$($passwordUnchangedLast90Days.Count)"
Write-Host "---------------" -ForegroundColor Red

$reversibleEncryption = Get-ADUser -Filter {(enabled -eq $true) -and (AllowReversiblePasswordEncryption -eq $true)} -Properties userAccountControl | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Number of Enabled Accounts with Reversible Encryption Enabled: $($reversibleEncryption.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Accounts with Reversible Encryption Enabled,$($reversibleEncryption.Count)"
Write-Host "---------------" -ForegroundColor Red

$preAuthDisabled = Get-ADUser -Filter {(enabled -eq $true) -and (DoesNotRequirePreAuth -eq $true)} -Properties userAccountControl | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Number of Enabled Accounts with Kerberos Pre-Auth Disabled: $($preAuthDisabled.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Enabled Accounts with Kerberos Pre-Auth Disabled,$($preAuthDisabled.Count)"
Write-Host "---------------" -ForegroundColor Red

$kerberosDES = Get-ADUser -Filter 'UserAccountControl -band 0x200000' -Properties userAccountControl | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Number of Enabled Accounts with Kerberos DES Encryption: $($kerberosDES.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Enabled Accounts with Kerberos DES Encryption,$($kerberosDES.Count)"
Write-Host "---------------" -ForegroundColor Red

$delegationUsers = Get-ADUser -Filter {(enabled -eq $true) -and (TrustedForDelegation -eq $true)} -Properties userAccountControl | Select SamAccountName -ExpandProperty SamAccountName
Write-Host "Number of Enabled Accounts Trusted for Unconstrained Delegation: $($delegationUsers.Count)" -ForegroundColor Green
Add-Content -Path $outputCSV -Value "'Number of Enabled Accounts Trusted for Unconstrained Delegation,$($delegationUsers.Count)"
Write-Host "---------------" -ForegroundColor Red
#-----------------------------------------------------
Write-Host "Script finished..." -ForegroundColor Green
