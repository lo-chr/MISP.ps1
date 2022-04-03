<#
.SYNOPSIS
    This script provides a command line interface for querying MISP (Malware Information Sharing Platform) via Powershell.

.DESCRIPTION
    The scripts connects to a certain MISP instance via the Invoke-RestMethod-Function of Powershell. It supports querying MISP by MISP event id and by attributes. It is able to store events, which are of special interest for the user.

.INPUTS
    None. You cannot pipe objects to MISP.ps1

.OUTPUTS
	The output is only generated via the command line interface.

.EXAMPLE
	PS> .\MISP.ps1

.LINK
	MISP Project Website: https://www.misp-project.org

.NOTES
    Author: Christoph Lobmeyer
    Last Edit: 2022-04-03
    Version 1.0 - initial release of MISP.ps1
#>


# Global variables for storing saved events and settings
$global:loadedMispEvents = New-Object System.Collections.ArrayList
$global:MispSettings = $null

# Function is responsible for saving the settings, necessary for the MISP-connection.
function Save-MispSettings() {
	param (
		$InstanceUri,
        $APIKey,
		$DebugMode
	)
    if($PSVersionTable.Platform -eq "Unix") {
        $StorePath = "~/.PSMISP/"
        if (-Not (Test-Path -Path $StorePath)) {
            $null = New-Item -Path "~/" -Name ".PSMISP" -ItemType "directory"
        }
	} elseif($Env:OS -eq "Windows_NT") {
		$StorePath = "$env:APPDATA\PSMISP\"
		if(-Not (Test-Path -Path $StorePath)) {
			$null = New-Item -Path "$env:APPDATA" -Name "PSMISP" -ItemType "directory"
		}
	}

	if(-not($InstanceUri -match '/\$')) {
		$InstanceUri  = "$InstanceUri/"
	}
	$global:MispSettings = @{
		'APIKey' = $APIKey
		'InstanceUri' = $InstanceUri
		'DebugMode' = $DebugMode
	}
	$global:MispSettings | ConvertTo-Json | Out-File ($StorePath+"settings.json")
}

# Function loads the configuration for the MISP connection.
function Get-MispConfiguration() {
    if($PSVersionTable.Platform -eq "Unix") {
        $StorePath = "~/.PSMISP/"
	} elseif($Env:OS -eq "Windows_NT") {
		$StorePath = "$env:APPDATA\PSMISP\"
	}
	if (Test-Path -Path ($StorePath+"settings.json")) {
		$global:MispSettings = Get-Content ($StorePath+"settings.json") | ConvertFrom-Json
	}
}

# Function tests/establishes the MISP connection.
function Test-MispConnection() {
	$MispRequestHeaders = @{
		'Authorization' = $global:MispSettings.APIKey
		'Accept' = 'application/json'
		'Content-Type' = 'application/json'
	}

	$RequestUri = $global:MispSettings.InstanceUri + "servers/getVersion"

	try {
		if((-not $global:MispSettings.DebugMode) -or ($null -eq $global:MispSettings.DebugMode)) {
			$result = Invoke-RestMethod -Uri $RequestUri -Method Get -Headers $MispRequestHeaders
			Write-Host -ForegroundColor green "Connection to MISP-Instance" $global:MispSettings.InstanceUri "with version" $result.version "successful."
		} else {
			$result = Invoke-RestMethod -Uri $RequestUri -Method Get -Headers $MispRequestHeaders -SkipCertificateCheck
			Write-Host -ForegroundColor green "Connection to MISP-Instance" $global:MispSettings.InstanceUri "with version" $result.version "successful."
		}
		return $true		
	} catch {
		Write-Host -ForegroundColor red "Error while connecting to MISP-Instance. Check the connection, the address of the instance and the API-Key. Maybe you have a self signed certificate and are not running in debug mode?"
		Write-Debug $_.ErrorDetails
		return $false
	}
}

# Function checks for a given event, if that event is already known (stored as a saved event).
function Get-MispEventKnownState {
	param (
		$MispEvent
	)

	# check if an event is already known (stored in saved events)
	foreach ($loadedEvent in $global:loadedMispEvents) {
		if($loadedEvent.id -eq $MispEvent.id) {
			return $true
		}
	}
	return $false
}

# Function gets a MISP Event by its ID
function Get-MispEventById() {
	param (
		$EventId
	)

	$MispRequestHeaders = @{
		'Authorization' = $global:MispSettings.APIKey
		'Accept' = 'application/json'
		'Content-Type' = 'application/json'
	}
	$RequestUri = $global:MispSettings.InstanceUri + "events/view/" + $EventId

	try {
		if((-not $global:MispSettings.DebugMode) -or ($null -eq $global:MispSettings.DebugMode)) {
			$result = Invoke-RestMethod -Uri $RequestUri -Method 'Get' -Headers $MispRequestHeaders
		} else {
			$result = Invoke-RestMethod -Uri $RequestUri -Method 'Get' -Headers $MispRequestHeaders -SkipCertificateCheck
		}
		return $result.Event
	} catch {
		return $null
	}
}

# Function searches for all MISP events, having a certain attribute value
function Search-MispEventsByAttribute() {
	param (
		$SearchAttribute
	)

	$MispRequestHeaders = @{
		'Authorization' = $global:MispSettings.APIKey
		'Accept' = 'application/json'
		'Content-Type' = 'application/json'
	}

	$MispSearch = @{
		returnFormat = "json"
		quickfilter = 1
		value = $SearchAttribute
	} | ConvertTo-Json

	$RequestUri = $global:MispSettings.InstanceUri + "events/restsearch/" + $EventId

	try {
		if((-not $global:MispSettings.DebugMode) -or ($null -eq $global:MispSettings.DebugMode)) {
			$result = Invoke-RestMethod -Uri $RequestUri -Method 'Post' -Headers $MispRequestHeaders -Body $MispSearch
		} else {
			$result = Invoke-RestMethod -Uri $RequestUri -Method 'Post' -Headers $MispRequestHeaders -SkipCertificateCheck -Body $MispSearch
		}
		return $result.response.Event
	} catch {
		return $null
	}
}

# Function adds MISP event to saved events
function Save-MispEvent() {
	param (
		$MispEvent
	)
	if (-not (Get-MispEventKnownState($MispEvent))) {
		$global:loadedMispEvents.Add($MispEvent) > $null

		if($PSVersionTable.Platform -eq "Unix") {
			$StorePath = "~/.PSMISP/"
		} elseif($Env:OS -eq "Windows_NT") {
			$StorePath = "$env:APPDATA\PSMISP\"
		}
		$global:loadedMispEvents | Select-Object -Property id, uuid, timestamp | ConvertTo-Json | Out-File ($StorePath+"events.json")
		Write-Host -ForegroundColor green "Event added sucessfully."
	} else {
		Write-Host -ForegroundColor red "Event is already on the list of saved events."
	}
}

# Function removes MISP event from saved events
function Remove-MispEventByID() {
	param (
		$MispEventID
	)

	# search event from saved list by event id, return true, if removal was successful
	foreach ($MispEvent in $global:loadedMispEvents) {
		if($MispEvent.id -eq $MispEventID) {
			$global:loadedMispEvents.Remove($MispEvent)
			if($PSVersionTable.Platform -eq "Unix") {
        		$StorePath = "~/.PSMISP/"
			} elseif($Env:OS -eq "Windows_NT") {
				$StorePath = "$env:APPDATA\PSMISP\"
			}
    		$global:loadedMispEvents | ConvertTo-Json | Out-File ($StorePath+"events.json")
			return $true
		}
	}
	return $false
}

# Function handles the menu, for a given MISP event
function Handle-MispEventResult() {
	param (
		$MispEvent
	)
	# handling for already known events
	$known = Get-MispEventKnownState($MispEvent)
	$MispEvent | Add-Member -MemberType NoteProperty -Name "known" -Value $known
	
	# Menu for handling MISP result
	Write-Host -ForegroundColor blue "Event with ID " $MispEvent.id "found."
	$RunMenu = $true
	while($RunMenu) {
		Write-Host -ForegroundColor blue "Available Actions: (A)dd event to saved events / (P)rint event details / (O)pen in browser / (B)ack to main menu"
		$key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
		
		# Handle add to saved events function 
		if (($key.Character -eq 'a') -or ($key.Character -eq 'A')) {
			if(-not $MispEvent.known) {
				Save-MispEvent($MispEvent)
			} else {
				Write-Host -ForegroundColor red "MISP event was already added to list of saved events."
			}
		}
		# Print event details
		elseif (($key.Character -eq 'p') -or ($key.Character -eq 'P')) {
			Write-MispEventDetail($MispEvent)
		}
		# Open event in browser
		elseif (($key.Character -eq 'o') -or ($key.Character -eq 'O')) {
			Open-MispEventById($MispEvent.id)
		}
		# Back to main menu
		elseif (($key.Character -eq 'b') -or ($key.Character -eq 'B')) {
			$RunMenu = $false
		}
	}
}

# Function loads the list of saved events.
function Get-SavedMispEventList() {
	if($PSVersionTable.Platform -eq "Unix") {
        $StorePath = "~/.PSMISP/"
	} elseif($Env:OS -eq "Windows_NT") {
		$StorePath = "$env:APPDATA\PSMISP\"
	}
	if (Test-Path -Path ($StorePath+"events.json")) {
		$global:loadedMispEvents.Clear()
		$savedMispEvents = Get-Content ($StorePath+"events.json") | ConvertFrom-Json
		$modifiedCounter = 0
		# Check if events have been changed since last run, add field for distinction (changed or not) and store new version of event (if applicable)
		foreach($savedEvent in $savedMispEvents) {
			$loadedEvent = Get-MispEventById($savedEvent.id)
			if(-not (($savedEvent.id -eq $loadedEvent.id) -and ($savedEvent.uuid -eq $loadedEvent.uuid) -and ($savedEvent.timestamp -eq $loadedEvent.timestamp))){
				$loadedEvent | Add-Member -MemberType NoteProperty -Name "modified" -Value $true
				$modifiedCounter++
			} else {
				$loadedEvent | Add-Member -MemberType NoteProperty -Name "modified" -Value $false
			}
			$loadedEvent | Add-Member -MemberType NoteProperty -Name "known" -Value $true
			$global:loadedMispEvents.Add($loadedEvent) > $null
		}
		Write-Host -ForegroundColor green "Loaded" $global:loadedMispEvents.Count "event(s) successfully." $modifiedCounter "event(s) has/have been modified."
	}
}

# Function opens the MISP event in a browser
function Open-MispEventById() {
	param (
		$MispEventId
	)
	$RequestUri = $global:MispSettings.InstanceUri + "events/view/" + $MispEventId
	Start-Process $RequestUri
}

# Function prints the output of a given MISP event
function Write-MispEventDetail {
	param (
		$MispEvent
	)
	
	$JoinedTags = ""
	foreach($Tag in $MispEvent.Tag) {
		$JoinedTags += $Tag.name+';'
	}
	
	# Print basic information of event
	$MispEvent | Format-List -Property @{ name = "Event ID";expression={$_.id}}, @{ name = "Info";expression={$_.info}},
									@{ name = "Threat Level";expression={ $_.threat_level_id -replace '1', "High" -replace '2', "Medium" -replace '3', "Low"}
									},
									@{
										name = 'Owner Org'
										expression={$_.Org.name}
									}, @{ name = "Date";expression={$_.date}},
									@{
										name = 'Last Change'
										expression={(Get-Date 01.01.1970)+([System.TimeSpan]::fromseconds([convert]::ToInt64($_.timestamp, 10)))}
									},
									@{ name = "Tags";expression={$JoinedTags}},
									@{ name = "Attributes Count";expression={$_.attribute_count}},
									@{ name = "Published? ";expression={$_.published}},
									@{ name = "Modified?";expression={$_.modified}}
	# Print attributes of event
	$MispEvent.Attribute | Format-Table -Property @{ name = "ID";expression={$_.id}}, @{ name = "Category";expression={$_.category}}, @{ name = "Type";expression={$_.type}},
												@{ name = "Value";expression={$_.value}}, @{ name = "Comment";expression={$_.comment}},
												@{
													name = 'Last Change'
													expression={(Get-Date 01.01.1970)+([System.TimeSpan]::fromseconds([convert]::ToInt64($_.timestamp, 10)))}
												}, @{ name = "IDS";expression={$_.to_ids}}
}

# Function prints a table for given MISP events
function Write-MispEventTable {
	param (
		$MispEvents
	)

	$MispEvents | Format-Table -AutoSize -Property @{ name = "Event ID";expression={$_.id}}, @{ name = "Info";expression={$_.info}},
									@{ name = "Threat Level";expression={ $_.threat_level_id -replace '1', "High" -replace '2', "Medium" -replace '3', "Low"}
									},
									@{
										name = 'Owner Org'
										expression={$_.Org.name}
									}, @{ name = "Date";expression={$_.date}},
									@{
										name = 'Last Change'
										expression={(Get-Date 01.01.1970)+([System.TimeSpan]::fromseconds([convert]::ToInt64($_.timestamp, 10)))}
									},
									@{ name = "Attributes";expression={$_.attribute_count}}, @{ name = "Published? ";expression={$_.published}},
									@{ name = "Modified?";expression={$_.modified}}
}

#### BEGIN of regular programm ####

# Initialize Programm
Get-MispConfiguration
Clear-Host
$MispConnectionEstablished = Test-MispConnection

# Handle error while connecting to MISP
if(-Not $MispConnectionEstablished)
{
	# MISP-Connection failed, check all fields of MISP settings
	Write-Host -ForegroundColor yellow "MISP-Settings:"
	$global:MispSettings | Format-List

	# Input for new settings
	Write-Host -ForegroundColor blue "Set new MISP-Settings to establish connection"
	Write-Host -ForegroundColor blue "Enter URI of MISP instance you want to access you want to access:"
	$InstanceUri = Read-Host
	Write-Host -ForegroundColor blue "Enter API-Key of MISP instance you want to access you want to access:"
	$APIKey = Read-Host
	Write-Host -ForegroundColor blue "Do you want to run in Debug-Mode? (Y)es / (N)o"
	$DebugModeInput = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
	if (($DebugModeInput.Character -eq 'y') -or ($DebugModeInput.Character -eq 'Y')) {
		$DebugMode = $true
	} else {
		$DebugMode = $false
	}
	Save-MispSettings -InstanceUri $InstanceUri -APIKey $APIKey -DebugMode $DebugMode
	Clear-Host
	$MispConnectionEstablished = Test-MispConnection
}

# Make sure, connection is established
if($MispConnectionEstablished) {
	# Get locally saved events
	Get-SavedMispEventList
	
	# While loop for interactive mode
	$run = $true
	while ($run) {
		# Handle the main menu and the inputs of the menu selection
		# "(D)isplay saved events / (A)ccess events by ID / (S)earch event by attribute"
		Write-Host -ForegroundColor blue "Use the following function keys to use Powershell-MISP:"
		Write-Host -ForegroundColor blue "(L)ist saved events / (R)emove event from saved events / (A)ccess event by ID / (S)earch event by attribute / (Q)uit"
		$key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
		# Handle display saved events
		if (($key.Character -eq 'l') -or ($key.Character -eq 'L')) {
			Get-SavedMispEventList ## might be a fix for "empty" event list (only event id contained)
			if($global:loadedMispEvents.Count -eq 0) {
				Write-Host -ForegroundColor red "No MISP event saved."  # Print if list is empty
			}
			Write-MispEventTable($global:loadedMispEvents)
		}
		# Handle removing event by ID
		elseif (($key.Character -eq 'r') -or ($key.Character -eq 'R')) {
			if($global:loadedMispEvents.Count -eq 0) {
				Write-Host -ForegroundColor red "No MISP event saved. Nothing to remove."
			} else {
				Write-Host -ForegroundColor blue "Enter ID you want to remove: "
				$id = Read-Host
				if(Remove-MispEventById($id)) {
					Write-Host -ForegroundColor green "Removed event id " $id
				} else {
					Write-Host -ForegroundColor green "No event with id $id saved"
				}	
			}
		}
		# Handle access event by ID
		elseif (($key.Character -eq 'a') -or ($key.Character -eq 'A')) {
			Write-Host -ForegroundColor blue "Enter ID you want to access: "
			$id = Read-Host
			$MispEvent = Get-MispEventById($id)
			if($null -eq $MispEvent) {
				Write-Host -ForegroundColor red "Events not found"
			} else {
				Handle-MispEventResult($MispEvent)
			}
		}
		# Search events by attribute
		elseif (($key.Character -eq 's') -or ($key.Character -eq 'S')) {
			Write-Host -ForegroundColor blue "Enter attribute you want to search for: "
			$query = Read-Host
			$MispEvents = Search-MispEventsByAttribute($query)
			if($null -eq $MispEvents) {
				Write-Host -ForegroundColor red "Events not found"
			} else {
				Write-MispEventTable($MispEvents)
			}
		}
		# Stop programm
		elseif (($key.Character -eq 'q') -or ($key.Character -eq 'Q')) {
			$run = $false	# Stop programm
			Clear-Host
		}
	}
} else {
	Write-Host -ForegroundColor red "No success connecting to MISP instance. Aborting..."
}