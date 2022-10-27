<#
  .SYNOPSIS
  �������� ������ ��������
  .DESCRIPTION
  ��������� ������ � ������ - ����������� ��� ����� ������������ � �������
  .EXAMPLE
  Remove-Yandex -ComputerName WS-00001
  .PARAMETER ComputerName
  ������������ �������� ��� ����������
#> 

    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, Position=0, HelpMessage="��� ����������� ������ ���������� � WS/WM/WN � ���� ������ 8 ��������")]
        [ValidatePattern('^W[S,M,N]-.....')]
        [System.String]$ComputerName
    )

Begin {  # �������� �����
    while ($ComputerName -notmatch "^W[S,M,N]-.....") {
	    [string]$ComputerName = ($(read-host "������� ��� ����������")).trim()
	    if ($ComputerName -notmatch "^W[S,M,N]-.....") { Write-Host ��� ����������� ������ ���������� � WS, WM ��� WN � ���� ������ 8 �������� -ForegroundColor Red }
    }

    if ($env:CredUserName) {
	    $username = $env:CredUserName
	    $pass = $env:CredUserPassword | ConvertTo-SecureString -Key (1..16)
	    $creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $pass
	    $PSentry = New-PSSession -ComputerName $ComputerName -Credential $creds -ErrorAction SilentlyContinue
	    } else { $PSentry = New-PSSession -ComputerName $ComputerName -ErrorAction SilentlyContinue}

    if (!($PSentry)) { 
        $Cred = Get-Credential -Message '����� ����� �������� ��������������'
        if ($cred) {
            $PSentry = New-PSSession -ComputerName $ComputerName -Credential $Cred -ErrorAction SilentlyContinue
            }
        if (!($PSentry)) {
            Write-Host ������������ � $ComputerName �� ������� -ForegroundColor Red
            return
            } else { 
		    $env:CredUserName = $cred.UserName
		    $env:CredUserPassword = $cred.Password | ConvertFrom-SecureString �Key (1..16)
		    }
        }
}

Process {  #��������
    Invoke-Command -Session $PSentry -ScriptBlock {
	
		function Add-Reestr {
			[CmdletBinding()]
			Param([Parameter(ValueFromPipelineByPropertyName)]$Name)
			process {
				# Regex pattern for SIDs
				$PatternSID = 'S-1-5-21-\d+-\d+\-\d+\-\d+$'
				# Get Username, SID, and location of ntuser.dat for all users
				$ProfileList = gp 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' | Where-Object {$_.PSChildName -match $PatternSID} | 
					Select  @{name="SID";expression={$_.PSChildName}}, 
							@{name="UserHive";expression={"$($_.ProfileImagePath)\ntuser.dat"}}, 
							@{name="Username";expression={$_.ProfileImagePath -replace '^(.*[\\\/])', ''}}
				$item = $ProfileList | where UserName -eq $Name
				$PathRun = Get-ItemProperty registry::HKEY_USERS\$($Item.SID)\Software\Microsoft\Windows\CurrentVersion\Run\
				$UninstallPath = Get-ItemProperty registry::HKEY_USERS\$($Item.SID)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
				$RemoveYandexBrowser = ($UninstallPath | where DisplayName -eq Yandex).UninstallString.replace("verbose-logging", " multi-install --chrome --system-level --force-uninstall")
				$RemoveYaPinLancher = ($UninstallPath | where DisplayName -eq '������ "������" �� ������ �����').UninstallString + " --force-uninstall"
				if ($PathRun -match "YandexSearchBand") {
					$PathRun | New-ItemProperty -Name RemoveYandexSearchBand -PropertyType String -Value $PathRun.YandexSearchBand.Replace("auto","uninstall") | Out-Null
					"��������� ������ ��� �������� ����� � ������ " + "{0}" -f $($item.Username) | Write-Output  
				}
				$PathRun | New-ItemProperty -Name RemoveYandexBrowser -PropertyType String -Value $RemoveYandexBrowser | Out-Null
				"��������� ������ ��� �������� YandexBrowser � ������ " + "{0}" -f $($item.Username) | Write-Output
				$PathRun | New-ItemProperty -Name RemoveYaPinLancher -PropertyType String -Value $RemoveYaPinLancher | Out-Null
				"��������� ������ ��� �������� YaPinLancher � ������ " + "{0}" -f $($item.Username) | Write-Output
			}
		}
		
	Get-ChildItem -Path C:\Users | Where-Object {Test-Path C:\Users\$_\AppData\Local\Yandex} | Add-Reestr
	}
}