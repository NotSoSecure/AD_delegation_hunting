<##############################################################################
Author : Anant Shrivastava for NotSoSecure Global Services
NotSoSecure will not be held liable if this script is used outside of lab environment and results in any loss or damage to anyone or anything.

This script loops through all the OU's and extracts the ACL for each of them. The ACL is extracted only when the user belongs to a specific domain and hence eliminates the entries for builtin users and non domain users. this then also filteres out any acl pointing to domain admins and enterprise admins and finally a csv sheet is created.

References used: https://blogs.technet.microsoft.com/ashleymcglone/2013/03/25/active-directory-ou-permissions-report-free-powershell-script-download/

##############################################################################>

Import-Module ActiveDirectory -WarningAction SilentlyContinue
# force use of specified credentials everywhere
$creds=Get-Credential
$PSDefaultParameterValues = @{"*-AD*:Credential"=$creds}

# GET DC Name
$dcname=(Get-ADDomainController).Name
New-PSDrive -Name AD -PSProvider ActiveDirectory -Server $dcname -Root //RootDSE/ -Credential $creds
Set-Location AD:

# House keeping, obtain domain name from system
$domain = (Get-ADDomain).Name
$groups_to_ignore = ( "$domain\Enterprise Admins", "$domain\Domain Admins")
# 'NT AUTHORITY\SYSTEM', 'S-1-5-32-548', 'NT AUTHORITY\SELF'

# This array will hold the report output.
$report = @()
$schemaIDGUID = @{}
### NEED TO RECONCILE THE CONFLICTS ###
$ErrorActionPreference = 'SilentlyContinue'
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name, schemaIDGUID |
 ForEach-Object {$schemaIDGUID.add([System.GUID]$_.schemaIDGUID,$_.name)}
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGUID |
 ForEach-Object {$schemaIDGUID.add([System.GUID]$_.rightsGUID,$_.name)}
$ErrorActionPreference = 'Continue'

# Get a list of all OUs.  Add in the root containers for good measure (users, computers, etc.).
$OUs  = @(Get-ADDomain | Select-Object -ExpandProperty DistinguishedName)
$OUs += Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty DistinguishedName
$OUs += Get-ADObject -SearchBase (Get-ADDomain).DistinguishedName -SearchScope OneLevel -LDAPFilter '(objectClass=container)' | Select-Object -ExpandProperty DistinguishedName

# Loop through each of the OUs and retrieve their permissions.
# Add report columns to contain the OU path and string names of the ObjectTypes.
# Only add when its identifyref matches domain name and is not part of ignore group
ForEach ($OU in $OUs) {
    $report += Get-Acl -Path "AD:\$OU" |
     Select-Object -ExpandProperty Access | ? {$_.IdentityReference -match "$domain*" -and $_.IdentityReference -notin $groups_to_ignore} | 
     Select-Object @{name='organizationalUnit';expression={$OU}}, `
                   @{name='objectTypeName';expression={if ($_.objectType.ToString() -eq '00000000-0000-0000-0000-000000000000') {'All'} Else {$schemaIDGUID.Item($_.objectType)}}}, `
                   @{name='inheritedObjectTypeName';expression={$schemaIDGUID.Item($_.inheritedObjectType)}}, `
                   *
}

# Show only non inherited explicitly assigned permissions
$filterrep= $report | Where-Object {-not $_.IsInherited}
# Dump the raw report out to a CSV file for analysis in Excel.
#$filterrep | Export-Csv -Path ".\delegation_hunter.csv" -NoTypeInformation
Write-Output ( $filterrep | Select-Object OrganizationalUnit,ObjectTypeName,ActiveDirectoryRights,IdentityReference | Format-Table | Out-String)