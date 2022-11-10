<#
  .SYNOPSIS
  Удаление яндекс браузера
  .DESCRIPTION
  Добавляет запись в реестр - срабатывает при входе пользователя в систему
  .EXAMPLE
  Remove-Yandex -ComputerName "WS-00001"
  .PARAMETER ComputerName
  Обязательный параметр имя компьютера
#>

    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, Position=0, HelpMessage="Имя компьютерая должно начинаться с WS/WM/WN и быть равным 8 символам")]
        [ValidatePattern('^W[S,M,N]-.{5}')]
        [System.String]$ComputerName
    )

Begin {  # Проверка ввода
    while ($ComputerName -notmatch "^W[S,M,N]-.{5}") {
	    [string]$ComputerName = ($(read-host "Укажите имя компьютера")).trim()
	    if ($ComputerName -notmatch "^W[S,M,N]-.{5}") { Write-Host Имя компьютерая должно начинаться с WS, WM или WN и быть равным 8 символам -ForegroundColor Red }
    }

    if ($env:CredUserName) {
	    $username = $env:CredUserName
	    $pass = $env:CredUserPassword | ConvertTo-SecureString -Key (1..16)
	    $creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $pass
	    $PSentry = New-PSSession -ComputerName $ComputerName -Credential $creds -ErrorAction SilentlyContinue
	    } else { $PSentry = New-PSSession -ComputerName $ComputerName -ErrorAction SilentlyContinue}

    if (!($PSentry)) {
        $Cred = Get-Credential -Message 'Нужны права сетевого администратора'
        if ($cred) {
            $PSentry = New-PSSession -ComputerName $ComputerName -Credential $Cred -ErrorAction SilentlyContinue
            }
        if (!($PSentry)) {
            Write-Host Подключиться к $ComputerName не удалось -ForegroundColor Red
            return
            } else {
		    $env:CredUserName = $cred.UserName
		    $env:CredUserPassword = $cred.Password | ConvertFrom-SecureString –Key (1..16)
		    }
        }
}

Process {  #удаление
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
				$RemoveYaPinLancher = ($UninstallPath | where DisplayName -eq 'Кнопка "Яндекс" на панели задач').UninstallString + " --force-uninstall"
				if ($PathRun -match "YandexSearchBand") {
					$PathRun | New-ItemProperty -Name RemoveYandexSearchBand -PropertyType String -Value $PathRun.YandexSearchBand.Replace("auto","uninstall") | Out-Null
					"Добавлена запись для удаления Алисы в реестр " + "{0}" -f $($item.Username) | Write-Output
				}
				$PathRun | New-ItemProperty -Name RemoveYandexBrowser -PropertyType String -Value $RemoveYandexBrowser | Out-Null
				"Добавлена запись для удаления YandexBrowser в реестр " + "{0}" -f $($item.Username) | Write-Output
				$PathRun | New-ItemProperty -Name RemoveYaPinLancher -PropertyType String -Value $RemoveYaPinLancher | Out-Null
				"Добавлена запись для удаления YaPinLancher в реестр " + "{0}" -f $($item.Username) | Write-Output
			}
		}

	Get-ChildItem -Path C:\Users | Where-Object {Test-Path C:\Users\$_\AppData\Local\Yandex} | Add-Reestr
	}
}
