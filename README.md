# Get-ADUserCertificate
simple powershell module to get single or all user/contact certificates from an AD with all related information including metadata

<#
	.SYNOPSIS 
	simple module to get single or all user/contact certificate from an AD
	look for a certificate in usercert, usercertificate, usersmimecertificate attributes for contact and user object
	2 functions available : Get-ADUserCertificate and Get-AllADUserCertificates
	the function are standalone and the code could be used outside the module easily. the only prerequisite is RSAT with AD cmdlets.

	.DESCRIPTION
	Require RSAT if used on non Domain Controller environment.
	Do not manage manual authentication to directory (to be managed in a future version)

	.EXAMPLE
	C:\PS> import-module Get-ADUserCertificate.psm1
	C:\PS> Remove-Module Get-ADUserCertificate
#>

<#
	.SYNOPSIS 
	get user certificate(s) from contact or user object from an AD
	look for a certificate in usercert, usercertificate, usersmimecertificate attributes for object contact and user

	.DESCRIPTION
	Require RSAT if used on non Domain Controller environment.
	You can use several search type entry : distinguishedName or SamAccountName/CN or Mail
	you can search in another forest/domain using parameter "server" (by default take the current domain for logged on user)
	you can export the certificates found in file using "exportcert" parameter (require a file with full path)

	.EXAMPLE
	Get-ADUserCertificate -searchtype distinguishedName -searchentry "CN=account,OU=testou1,OU=testou,DC=ad,DC=ad,DC=com" -exportcert "C:\test\test\test.cer"
	Get-ADUserCertificate -searchtype Mail -searchentry "user.account@test.com"
	Get-ADUserCertificate -searchtype SamAccountNameOrCN -searchentry "UserAccount1" -server anotherad.ad.com
	
#>

<#
	.SYNOPSIS 
	get all user certificate(s) from all contact or user objects from an AD
	look for a certificate in usercert, usercertificate, usersmimecertificate attributes for all contact and user objects

	.DESCRIPTION
	Require RSAT if used on non Domain Controller environment.
	you can search in another forest/domain using parameter "server" (by default take the current domain for logged on user)
	you can export the certificates found in file using "exportcert" parameter (require a file with full path)
	you can skip warning message with user input using "skipconfirm" parameter

	.EXAMPLE
	Get-ADUserCertificate -exportcert "C:\test\test2"
	Get-ADUserCertificate -skipconfirm $true
	Get-ADUserCertificate -server anotherad.ad.com
	
#>
