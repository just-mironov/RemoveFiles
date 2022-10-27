<#
  .SYNOPSIS
  Простое удаление файлов
  .DESCRIPTION
  Используется подключение через PowerShell Session
  .EXAMPLE
  Remove-Files -ComputerName WS-02922 -Path "C:\Program Files\WindowsApps"
  .PARAMETER ComputerName
  Обязательный параметр имя компьютера где нужно удалить файлы или папки
  .PARAMETER Path
  Обязательный параметр путь до файла или папки
  .PARAMETER Confirm
  Необязательный параметр подтверждение, по умолчанию true
#> 

    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, Position=0, HelpMessage="Имя компьютерая должно начинаться с WS/WM/WN и быть равным 8 символам")]
	#	[ValidatePattern(("^W[S,M,N]-.....|")]
        [System.String]$ComputerName,      
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, Position=1, HelpMessage="Путь до файла начинается с C:\ или D:\")]
        [ValidatePattern("^[C,D]\:\\")]  
        [string]$Path,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true, Position=2, HelpMessage="Нужно ли подтверждение удаления")] 
        [switch[]]$Confirm = $true
    )

# Проверка ввода
while ( !($PatternComputerName -or $PatternIPAddress) ) {
    [string]$InputString = ($(read-host "Укажите IP или Имя компьютера")).trim()

    $PatternComputerName = $InputString -match "^W[S,M,N]-....."
    $PatternIPAddress = $InputString.StartsWith("172.") -and [ipaddress]::TryParse($InputString,[ref][ipaddress]::Loopback)
} 

while ($Path -notmatch "^[C,D]\:\\") {
	[string]$Path = ($(read-host "Укажите путь (enter для C:\Program Files\windowsapps\)")).trim()
	if ($Path.length -eq 0) { $Path = "C:\Program Files\windowsapps\" }
	if ($Path -notmatch "^[C,D]\:\\") { Write-Host Путь до файла начинается с C:\ или D:\ -ForegroundColor Red }
} 

# Проверка доступности
try {
	if ($PatternIPAddress) { 
		$ComputerName = [System.Net.Dns]::GetHostEntry([ipaddress]$InputString).hostname 
		} else {
		$ComputerName = $InputString
		}
    Test-Connection -ComputerName $ComputerName -Count 1 -ErrorAction Stop 
} catch {
    $ErrorMsg = $_.Exception.Message
}
if ($ErrorMsg) { 
    Write-Host $ErrorMsg -ForegroundColor Red 
    return
    }

# Сохранение пароля
if ($env:CredUserName) {
	$username = $env:CredUserName
	$pass = $env:CredUserPassword | ConvertTo-SecureString -Key (1..16)
	$creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $pass
	$PSentry = New-PSSession -ComputerName $ComputerName -Credential $creds -ErrorAction SilentlyContinue
	} else { $PSentry = New-PSSession -ComputerName $ComputerName -ErrorAction SilentlyContinue}

# Проверка подключения
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

# Проверка наличие папки
if (!(Invoke-Command -Session $PSentry -ScriptBlock {Test-Path -Path $Using:Path})) {
    Write-Host Папка/файл $Path не найдена на $ComputerName -ForegroundColor Red
    return
    }

if (!(Invoke-Command -Session $PSentry -ScriptBlock {Test-Path -Path $Using:Path*})) {
    Write-Host Папка/файл $Path на $ComputerName пустая -ForegroundColor Red
    return
    }

# Подсчёт файлов и папок
    $Command = {
        $DataColl = @() 
        Get-ChildItem -Path $Using:Path -ErrorAction SilentlyContinue |% {
	    <#  Подсчёт занимаемого места off
            $len = 0
            Get-ChildItem -Recurse -Force $_.fullname -ErrorAction SilentlyContinue | % { $len += $_.length }
            $Size = '{0:N2}' -f ($len / 1Mb)
            $CountFiles = (gci -Recurse -Force $_.FullName).count
	    #>	
            $ParentPath = $_.PSParentPath.Remove(0, 38) # Удаление строки Microsoft.PowerShell.Core\FileSystem::

            $PathProperties = New-Object PSObject # Необходимо создать новый объект, тк текущий передаётся целиком 
        #   Add-Member -InputObject $PathProperties -MemberType NoteProperty -Name CountFiles -Value $CountFiles 
        #   Add-Member -InputObject $PathProperties -MemberType NoteProperty -Name Size -Value $Size
            Add-Member -InputObject $PathProperties -MemberType NoteProperty -Name ParentPath -Value $ParentPath
            Add-Member -InputObject $PathProperties -MemberType NoteProperty -Name Name -Value $_.Name
            Add-Member -InputObject $PathProperties -MemberType NoteProperty -Name Attributes -Value $_.Attributes
            $DataColl += $PathProperties
        }
        $DataColl
    }

    # Выбор удаляемых элементов
    $DataColl = Invoke-Command -Session $PSentry -ScriptBlock $Command

# Нужно ли подтверждение удаляемых файлов?
if ($Confirm) {
    $UserChoice = $DataColl | select Attributes, ParentPath, Name <#,Size, CountFiles #> | Sort-Object Name -Descending | 
    Out-GridView -OutputMode Multiple -Title "Какие папки/файлы нужно удалить?"
    } else {
    $UserChoice = $DataColl | select Attributes, ParentPath, Name
    }

# Удаление
if ($UserChoice) {
	
	#определение разрядности
	$is64bit = Invoke-Command -Session $PSentry -ScriptBlock { (gwmi win32_operatingsystem).osarchitecture -match 64 }
	if ($is64bit) { 
	$handleEXE = "\\WS-02922\scripts\RemoveFiles\handle64.exe"
	$handleRemote = "C:\Windows\Temp\handle64.exe"
		} else { 
	$handleEXE = "\\WS-02922\scripts\RemoveFiles\handle.exe"
	$handleRemote = "C:\Windows\Temp\handle.exe"
	}
	
	#Копирование handle
	$check = Invoke-Command -Session $PSentry -ScriptBlock { Test-Path -Path $Using:handleRemote }
	if ( !($check) ) { Copy-Item -Path $handleEXE -Destination C:\Windows\Temp\ -ToSession $PSentry -Force }
	
    Invoke-Command -Session $PSentry -ScriptBlock {
        
	#Удаление подключений к процессам
	function Remove-Handle ($FilePath) {
		$Handle64 = $Using:handleRemote
		
		if ( !(Test-Path -Path $FilePath) -or !(Test-Path -Path $Handle64) ) { return $false }

		$Name = $FilePath -replace ".*\\"
		$BlockedHandles = @()
		
		# поиск процессов
		$handleOut = & $Handle64 $Name -accepteula -nobanner
	
		foreach ($line in $handleOut) {
            if ($line -match "^([\w\.]+)\s+pid\:\s(\d+).+\s\s(\w+)\:") {
                $prop = New-Object PSObject -Property ([ordered]@{
                Name = $Matches[1]
                PID = $Matches[2]
                Handle = $Matches[3] 
                })
                $BlockedHandles += $prop
            }
        }
		# остановка подключений
		if ($BlockedHandles) {   
			foreach ($Handle in $BlockedHandles) {
				Write-Host Файл $Name заблокирован $Handle.Name, отключаю... 
				$answ +=  & $Handle64 -p $Handle.pid -c $Handle.handle -y
			}
			
			# попытка ещё раз удалить
			try {
				Remove-Item -Path $FilePath -Force -ErrorAction Stop
				write-host Файл $Name удалён -ForegroundColor Yellow
				return $true
			} catch {
				$ErrorMsg = $_.Exception.Message
				return $false
			}
		}
	return $false
	} # конец функции удаления handles

        # получение списка файлов
        foreach ($File in $Using:UserChoice) {
            $FullName = $File.ParentPath + "\" + $File.Name
            [System.Array]$FilesPath += $FullName
            if ((Get-Item -Path $FullName).PSisContainer) {
                $FilesPath += (Get-ChildItem -Path $FullName -Recurse -Force).FullName
            }
        }
        [array]::Reverse($FilesPath)

        foreach($File in $FilesPath) {
            Try {
                Remove-Item -Path $File -Force -Verbose -ErrorAction Stop
            } Catch {
                $ErrorMsg = $_.Exception.Message 
                if ( !(Remove-Handle ($File)) ) {
                    Write-Host $ErrorMsg -ForegroundColor Red
                    }
            }
        }
    }
 
    Remove-PSSession $PSentry
}