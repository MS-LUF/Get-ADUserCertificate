#
# Created by: lucas.cueff[at]lucas-cueff.com.com
#
# Released on: 11/2017
#
#'(c) 2017 - Distributed under Artistic Licence 2.0 (https://opensource.org/licenses/artistic-license-2.0).'
#
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

Function Get-ADUserCertificate { 
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
	[CmdletBinding()] 
	Param( 
		  [parameter(Mandatory=$True)] 
		  [ValidateSet('Mail','SamAccountNameOrCN','distinguishedName')]
		  [String]$searchtype,
		  [parameter(Mandatory=$True)] 
		  [String]$searchentry,
		  [parameter(Mandatory=$false)] 
		  [ValidatePattern('^[a-zA-Z]:\\(((?![<>:"/\\|?*]).)+((?<![ .])\\)?)*$')]
		  [String]$exportcert,
		  [parameter(Mandatory=$false)] 
		  [ValidatePattern('^(?=.{1,254}$)((?=[a-z0-9-]{1,63}\.)(xn--+)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}$')]
		  [String]$server
	) 
	# import AD Module		  
	try {
		import-module ActiveDirectory
	} catch {
		write-warning "Not able to load active directory module"
		write-warning "Please check if RSAT is installed"
		write-error "Error Type: $($_.Exception.GetType().FullName)"
		write-error "Error Message: $($_.Exception.Message)"
		return 
	}
	# get current domain if necessary
	if (-not $server) {
		$server = (get-addomain -current loggedonuser).dnsroot
		$pdc = (get-addomain -current loggedonuser).PDCEmulator
	} Else {
		$pdc = (get-addomain -server $server).PDCEmulator
	}
	# prepare exportcert content
	if ($exportcert) {
		if ($exportcert -like "*.cer") {
			$exportpath = split-path -path $exportcert
			$exportfilebase = split-path -Leaf $exportcert
		} Else {
			write-warning "the file name and path provided are not containing a valid CER file with full path entry. ex : c:\temp 2\temp\test.cer"
			return
		}
	}
	# retrieve AD object based on distinguishedName, SamAccountName Or CN or mail
	switch ($searchtype) {
		"distinguishedName" {
			If ($searchentry -like "CN=*") {
				try {
					$searchpattern = get-adobject -Filter { ((objectclass -eq "user") -or (objectclass -eq "contact")) -and (distinguishedName -eq $searchentry)} -server $server -Properties objectClass,distinguishedname,displayName,mail,UserCertificate,UserSMIMECertificate,UserCert,sn,givenname
				} catch {
					write-error "Error Type: $($_.Exception.GetType().FullName)"
					write-error "Error Message: $($_.Exception.Message)"
					return 
				}
			}
		}
		"Mail" {
			IF ($searchentry -match "^[a-zA-Z0-9.!£#$%&'^_`{}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$") {
				try {
					$searchpattern = get-adobject -Filter { ((objectclass -eq "user") -or (objectclass -eq "contact")) -and (mail -eq $searchentry)} -server $server -Properties objectClass,distinguishedname,displayName,mail,UserCertificate,UserSMIMECertificate,UserCert,sn,givenname
				} catch {
					write-error "Error Type: $($_.Exception.GetType().FullName)"
					write-error "Error Message: $($_.Exception.Message)"
					return 
				}
			} 
		}
		"SamAccountNameOrCN" {
			If ($searchtype -eq "SamAccountNameOrCN") {
				try {
					$searchpattern = get-adobject -Filter { ((objectclass -eq "user") -or (objectclass -eq "contact")) -and ((sAMAccountName -eq $searchentry) -or (CN -eq $searchentry))} -server $server -Properties objectClass,distinguishedname,displayName,mail,UserCertificate,UserSMIMECertificate,UserCert,sn,givenname
				} catch {
					write-error "Error Type: $($_.Exception.GetType().FullName)"
					write-error "Error Message: $($_.Exception.Message)"
					return
				}
			}
		}
		#default {}
	}
	If ($searchpattern) {
		# Preparing new object
		$global:UserTemplateObject = New-Object psobject
		$UserTemplateObject | Add-Member -MemberType NoteProperty -Name ObjectClass -Value $null
		$UserTemplateObject | Add-Member -MemberType NoteProperty -Name distinguishedname -Value $null
		$UserTemplateObject | Add-Member -MemberType NoteProperty -Name displayName -Value $null
		$UserTemplateObject | Add-Member -MemberType NoteProperty -Name UserSMIMECertificate -Value $null
		$UserTemplateObject | Add-Member -MemberType NoteProperty -Name UserCertificate -Value $null
		$UserTemplateObject | Add-Member -MemberType NoteProperty -Name UserCert -Value $null
		$UserTemplateObject | Add-Member -MemberType NoteProperty -Name mail -Value $null
		$UserTemplateObject | Add-Member -MemberType NoteProperty -Name givenname -Value $null
		$UserTemplateObject | Add-Member -MemberType NoteProperty -Name sn -Value $null
		$UserTemplateObject | Add-Member -MemberType NoteProperty -Name UserSMIMECertificateLastOriginatingChangeTime -Value $null
		$UserTemplateObject | Add-Member -MemberType NoteProperty -Name UserSMIMECertificateLastOriginatingDeleteTime -Value $null
		$UserTemplateObject | Add-Member -MemberType NoteProperty -Name UserCertificateLastOriginatingChangeTime -Value $null
		$UserTemplateObject | Add-Member -MemberType NoteProperty -Name UserCertificateLastOriginatingDeleteTime -Value $null
		$UserTemplateObject | Add-Member -MemberType NoteProperty -Name UserCertLastOriginatingChangeTime -Value $null
		$UserTemplateObject | Add-Member -MemberType NoteProperty -Name UserCertLastOriginatingDeleteTime -Value $null
		# check the certificate presence
		If ($searchpattern.UserSMIMECertificate) {
			$cer1 = new-object System.Security.Cryptography.X509Certificates.X509Certificate2 $searchpattern.UserSMIMECertificate
			$cer1metadata = Get-ADReplicationAttributeMetadata $searchpattern.distinguishedName -properties usersmimecertificate -Server $pdc
		} Else {
			write-warning "no certificate in UserSMIMECertificate attribute for object $($searchpattern.distinguishedname)"
		}
		If ($searchpattern.UserCertificate) {	
			$cer2 = new-object System.Security.Cryptography.X509Certificates.X509Certificate2 $searchpattern.UserCertificate
			$cer2metadata = Get-ADReplicationAttributeMetadata $searchpattern.distinguishedName -properties usercertificate -Server $pdc
		} Else {
			write-warning "no certificate in UserCertificate attribute for object $($searchpattern.distinguishedname)"
		}
		If ($searchpattern.UserCert) {	
			$cer3 = new-object System.Security.Cryptography.X509Certificates.X509Certificate2 $searchpattern.UserCert
			$cer3metadata = Get-ADReplicationAttributeMetadata $searchpattern.distinguishedName -properties usercert -Server $pdc
		} Else {
			write-warning "no certificate in UserCert attribute for object $($searchpattern.distinguishedname)"
		}
		#building new object with content
		$ObjCertUser = $UserTemplateObject | Select-Object *
		$ObjCertUser.ObjectClass = $searchpattern.ObjectClass
		$ObjCertUser.distinguishedname = $searchpattern.distinguishedname
		$ObjCertUser.displayName = $searchpattern.displayName
		if($cer1) {
			$ObjCertUser.UserSMIMECertificate = $cer1
			$ObjCertUser.UserSMIMECertificateLastOriginatingChangeTime = $cer1metadata.LastOriginatingChangeTime
			$ObjCertUser.UserSMIMECertificateLastOriginatingDeleteTime = $cer1metadata.LastOriginatingDeleteTime
			if ($exportcert) {
				$exportfile1 = $exportfilebase -replace ".cer","_$($searchentry)_USMcrt.cer"
				$exportcertfn = join-path ($exportpath) ($exportfile1)
				if (-not (test-path $exportcertfn)) {
					$cer1.rawdata | set-content "$($exportcertfn)" -Encoding Byte
				} Else {
					write-warning "cannot create $($exportcertfn) - file already exists"
				}
			}
		}
		if ($cer2) {
			$ObjCertUser.UserCertificate = $cer2
			$ObjCertUser.UserCertificateLastOriginatingChangeTime = $cer2metadata.LastOriginatingChangeTime
			$ObjCertUser.UserCertificateLastOriginatingDeleteTime = $cer2metadata.LastOriginatingDeleteTime
			if ($exportcert) {
				$exportfile2 = $exportfilebase -replace ".cer","_$($searchentry)_Ucrtf.cer"
				$exportcertfn = join-path ($exportpath) ($exportfile2)
				if (-not (test-path $exportcertfn)) {
					$cer2.rawdata | set-content "$($exportcertfn)" -Encoding Byte
				} Else {
					write-warning "cannot create $($exportcertfn) - file already exists"
				}
			}
		}
		if ($cer3) {
			$ObjCertUser.UserCert = $cer3
			$ObjCertUser.UserCertLastOriginatingChangeTime = $cer3metadata.LastOriginatingChangeTime
			$ObjCertUser.UserCertLastOriginatingDeleteTime = $cer3metadata.LastOriginatingDeleteTime
			if ($exportcert) {
				$exportfile2 = $exportfilebase -replace ".cer","_$($searchentry)_Ucrt.cer"
				$exportcertfn = join-path ($exportpath) ($exportfile2)
				if (-not (test-path $exportcertfn)) {
					$cer2.rawdata | set-content "$($exportcertfn)" -Encoding Byte
				} Else {
					write-warning "cannot create $($exportcertfn) - file already exists"
				}
			}
		}
		$ObjCertUser.mail = $searchpattern.mail
		$ObjCertUser.givenname = $searchpattern.givenname
		$ObjCertUser.sn = $searchpattern.sn
		#send back the new object as output
		return $ObjCertUser
	} Else {
		write-warning "no user or contact AD object found with your criteria : $($searchentry)"
		return 
	}
}

Function Get-AllADUserCertificates { 
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
	[CmdletBinding()] 
	Param( 
		  [parameter(Mandatory=$false)] 
		  [ValidatePattern('^(?=.{1,254}$)((?=[a-z0-9-]{1,63}\.)(xn--+)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}$')]
		  [String]$server,
		  [parameter(Mandatory=$false)] 
		  [ValidatePattern('^[a-zA-Z]:\\(((?![<>:"/\\|?*]).)+((?<![ .])\\)?)*$')]
		  [String]$exportcert,
		  [parameter(Mandatory=$false)]
		  [bool]$skipconfirm
	) 
	# warning message if parameter "skipconfirm" is not used
	if ($skipconfirm -eq $false) {
		write-warning "this cmdlet will get all certificates from your AD for user and contact objects. It may overload your directory, please use it carefully !"
		Write-Host "Press any key to continue ..." -foreground "green"
		$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | out-null
	}
	# import AD Module		  
	try {
		import-module ActiveDirectory
	} catch {
		write-warning "Not able to load active directory module"
		write-warning "Please check if RSAT is installed"
		write-error "Error Type: $($_.Exception.GetType().FullName)"
		write-error "Error Message: $($_.Exception.Message)"
		return 
	}
	# get current domain if necessary
	if (-not $server) {
		$server = (get-addomain -current loggedonuser).dnsroot
		$pdc = (get-addomain -current loggedonuser).PDCEmulator
	} Else {
		$pdc = (get-addomain -server $server).PDCEmulator
	}
	# prepare exportcert content
	if ($exportcert) {
		$exportpath = split-path -path $exportcert
	}
	#get info from AD
	try {
		$searchresult = @(get-adobject -Filter { ((objectclass -eq "user") -or (objectclass -eq "contact")) -and ((UserCertificate -like "*") -or (UserCert -like "*") -or (UserSMIMECertificate -like "*"))} -server $server -Properties objectClass,distinguishedname,displayName,mail,UserCertificate,UserSMIMECertificate,UserCert,sn,givenname)
	} catch {
		write-error "Error Type: $($_.Exception.GetType().FullName)"
		write-error "Error Message: $($_.Exception.Message)"
		return 
	}
	# Preparing new object
	$FinalObjCertUser = @()
	$global:UserTemplateObject = New-Object psobject
	$UserTemplateObject | Add-Member -MemberType NoteProperty -Name ObjectClass -Value $null
	$UserTemplateObject | Add-Member -MemberType NoteProperty -Name distinguishedname -Value $null
	$UserTemplateObject | Add-Member -MemberType NoteProperty -Name displayName -Value $null
	$UserTemplateObject | Add-Member -MemberType NoteProperty -Name UserSMIMECertificate -Value $null
	$UserTemplateObject | Add-Member -MemberType NoteProperty -Name UserCertificate -Value $null
	$UserTemplateObject | Add-Member -MemberType NoteProperty -Name UserCert -Value $null
	$UserTemplateObject | Add-Member -MemberType NoteProperty -Name mail -Value $null
	$UserTemplateObject | Add-Member -MemberType NoteProperty -Name givenname -Value $null
	$UserTemplateObject | Add-Member -MemberType NoteProperty -Name sn -Value $null
	$UserTemplateObject | Add-Member -MemberType NoteProperty -Name UserSMIMECertificateLastOriginatingChangeTime -Value $null
	$UserTemplateObject | Add-Member -MemberType NoteProperty -Name UserSMIMECertificateLastOriginatingDeleteTime -Value $null
	$UserTemplateObject | Add-Member -MemberType NoteProperty -Name UserCertificateLastOriginatingChangeTime -Value $null
	$UserTemplateObject | Add-Member -MemberType NoteProperty -Name UserCertificateLastOriginatingDeleteTime -Value $null
	$UserTemplateObject | Add-Member -MemberType NoteProperty -Name UserCertLastOriginatingChangeTime -Value $null
	$UserTemplateObject | Add-Member -MemberType NoteProperty -Name UserCertLastOriginatingDeleteTime -Value $null
	# doing the main stuff
	write-host "$($search.count) certificates found." -foreground "green"
	foreach ($result in $searchresult) {
		# check the certificate presence
		If ($result.UserSMIMECertificate) {
			$cer1 = new-object System.Security.Cryptography.X509Certificates.X509Certificate2 $result.UserSMIMECertificate
			$cer1metadata = Get-ADReplicationAttributeMetadata $searchpattern.distinguishedName -properties usersmimecertificate -Server $pdc
		} Else {
			write-warning "no certificate in UserSMIMECertificate attribute for object $($result.distinguishedname)"
		}
		If ($result.UserCertificate) {	
			$cer2 = new-object System.Security.Cryptography.X509Certificates.X509Certificate2 $result.UserCertificate
			$cer2metadata = Get-ADReplicationAttributeMetadata $searchpattern.distinguishedName -properties usercertificate -Server $pdc
		} Else {
			write-warning "no certificate in UserCertificate attribute for object $($result.distinguishedname)"
		}
		If ($result.UserCert) {	
			$cer3 = new-object System.Security.Cryptography.X509Certificates.X509Certificate2 $result.UserCert
			$cer3metadata = Get-ADReplicationAttributeMetadata $searchpattern.distinguishedName -properties usercert -Server $pdc
		} Else {
			write-warning "no certificate in UserCert attribute for object $($result.distinguishedname)"
		}
		#building new object with content
		$ObjCertUser = $UserTemplateObject | Select-Object *
		$ObjCertUser.ObjectClass = $result.ObjectClass
		$ObjCertUser.distinguishedname = $result.distinguishedname
		$ObjCertUser.displayName = $result.displayName
		if($cer1) {
			$ObjCertUser.UserSMIMECertificate = $cer1
			$ObjCertUser.UserSMIMECertificateLastOriginatingChangeTime = $cer1metadata.LastOriginatingChangeTime
			$ObjCertUser.UserSMIMECertificateLastOriginatingDeleteTime = $cer1metadata.LastOriginatingDeleteTime
			if ($exportcert) {
				$exportfile1 = $exportfilebase -replace ".cer","_$($result.distinguishedname)_USMcrt.cer"
				$exportcertfn = join-path ($exportpath) ($exportfile1)
				if (-not (test-path $exportcertfn)) {
					$cer1.rawdata | set-content "$($exportcertfn)" -Encoding Byte
				} Else {
					write-warning "cannot create $($exportcertfn) - file already exists"
				}
			}
		}
		if ($cer2) {
			$ObjCertUser.UserCertificate = $cer2
			$ObjCertUser.UserCertificateLastOriginatingChangeTime = $cer2metadata.LastOriginatingChangeTime
			$ObjCertUser.UserCertificateLastOriginatingDeleteTime = $cer2metadata.LastOriginatingDeleteTime
			if ($exportcert) {
				$exportfile2 = $exportfilebase -replace ".cer","_$($result.distinguishedname)_Ucrtf.cer"
				$exportcertfn = join-path ($exportpath) ($exportfile2)
				if (-not (test-path $exportcertfn)) {
					$cer2.rawdata | set-content "$($exportcertfn)" -Encoding Byte
				} Else {
					write-warning "cannot create $($exportcertfn) - file already exists"
				}
			}
		}
		if ($cer3) {
			$ObjCertUser.UserCert = $cer3
			$ObjCertUser.UserCertLastOriginatingChangeTime = $cer3metadata.LastOriginatingChangeTime
			$ObjCertUser.UserCertLastOriginatingDeleteTime = $cer3metadata.LastOriginatingDeleteTime
			if ($exportcert) {
				$exportfile2 = $exportfilebase -replace ".cer","_$($result.distinguishedname)_Ucrt.cer"
				$exportcertfn = join-path ($exportpath) ($exportfile2)
				if (-not (test-path $exportcertfn)) {
					$cer2.rawdata | set-content "$($exportcertfn)" -Encoding Byte
				} Else {
					write-warning "cannot create $($exportcertfn) - file already exists"
				}
			}
		}
		$ObjCertUser.mail = $searchpattern.mail
		$ObjCertUser.givenname = $searchpattern.givenname
		$ObjCertUser.sn = $searchpattern.sn
		$FinalObjCertUser += $ObjCertUser
	}
	return $FinalObjCertUser
}

Export-ModuleMember -Function Get-ADUserCertificate, Get-AllADUserCertificates