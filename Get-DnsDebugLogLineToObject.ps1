
function Get-DnsDebugLogLineToObject(
    	[Parameter(Mandatory=$true,
                   HelpMessage='Full DNS debug log file')]
    	[ValidateScript({Test-Path ($_)})]
    	[string] $DNSDebugLogFilePath,
        [Parameter(Mandatory=$false,
                   HelpMessage='Fully Qualified DNS server name that created the log file')]
        [string] $DnsServerName='',
        [Parameter(Mandatory=$false,
                   HelpMessage='DNS server Timezone offset. +/-00 from GMT')]
        [string] $DnsServerTzOffset='',
        [Parameter(Mandatory=$false,
                   HelpMessage='Ignore these types of queries')]
        [array] $IgnoreQryType=@(),
        [Parameter(Mandatory=$false,
                   HelpMessage='Tail the file instead of fully parsing it')]
        [switch] $t=$false
    ) {

    <#
    .SYNOPSIS
    Reads the specified DNS debug log and returns an object for each line

    .DESCRIPTION
    Retrives all DNS query entries (Context:PACKET) in the specified DNS debug log for further processing in Powershell.
    Entries in the file that are not of context PACKET are ignored.
    Incoming query request and response log lines can be parsed.
    The entire file can be processed or the tail option allows continuous monitoring of the file.

    .PARAMETER DNSDebugLogFilePath
    Specifies the filepath to the DNS debug logfile.

    .PARAMETER DnsServerName
    The fully qualified name of the DNS server that created the log file.  
    An attempt is made to populate this by default if run on the DNS server.

    .PARAMETER DnsServerTzOffset
    The timezone offset of DNS server from GMT in the format +/-00
    An attempt is made to populate this by default if run on the DNS server.

    .PARAMETER IgnoreQryType
    Ignore these types of queries.  An array of query types PTR, MX, AAAA, etc.

    .PARAMETER t
    Switch to enable monitoring of the file via Tail.

    .INPUTS
    Takes the filepath of the DNS server's debug log
    DNS server name that create the log file
    Ignore array contents of query types
    Option to enable continuous monitoring of the log file

    .OUTPUTS
    Pipelined PSCustom objects, see DNSLogEntryFactory function

    .EXAMPLE
    Get-DNSDebugLogLineToObject -DNSDebugLogFilePath "$($env:SystemRoot)\system32\dns\dns.log" -DnsServerName 'serv1.fqdomain.com'

    .EXAMPLE
    Get-DNSDebugLogLineToObject -DnsDebugLogFilePath "c:\dns.log" -DnsServerName 'my_server.dom.com' `
                                -DnsServerTzOffset '-04'

    .EXAMPLE
    Ignore Pointer and Mailexchange queries
    Get-DNSDebugLogLineToObject -DNSDebugLogFilePath "c:\dns.log" -DnsServerName 'serv1.fqdomain.com' `
                                -DnsServerTzOffset '-04' -IgnoreQryType @('PTR','MX')

    .LINK

    .NOTES
    You need at lease PS v3.0 for Tail to work.  If processing the entire file, PS v2.0 can be used.
    
	Author:
	Don Hess
	Version History:
    1.0    2016-05-06   Release
    #>
Begin {
    # Halt on any error
    $ErrorActionPreference = "Stop"

    # Change switch paramater to boolean
    Try {
        if ( $t.GetType().Name -eq 'SwitchParameter' ) {
        	$t_temp = $t.ToBool()
        	Remove-Variable t
        	$t = $t_temp    # Scoping should be wide enough
            Remove-Variable t_temp
        }
    }
    Catch { $t = $false }
    $htQRLookup = @{''='Query';' '='Query';'R'='Response';
                               'Query'=' ';'Response'='R';} # Dual directional, Accounts for a trimmed Query result also
    $htOpCodeLookup = @{'Q'='Standard Query';'N'='Notify';'U'='Update';'?'='Unknown';
                        'Standard Query'='Q';'Notify'='N';'Update'='U';'Unknown'='?';} # Dual directional
    $htFlagsCharCodeLookup = @{[char] 'A'='Authoritative Answer';[char] 'T'='Truncated Response';[char] 'D'='Recursion Desired';[char] 'R'='Recursion Available';
                               'A'='Authoritative Answer';'T'='Truncated Response';'D'='Recursion Desired';'R'='Recursion Available';
                               'Authoritative Answer'='A';'Truncated Response'='T';'Recursion Desired'='D';'Recursion Available'='R';} # Dual directional
    function DNSLogEntryFactory([int] $iCount=1) {
    	# Create a DNSPacketLogEntry object(s)
    	# Input:  Number of objects needed
    	# Returns: Array of blank objects
    	$aReturned = @()
    	for ($i = 0; $i -lt $iCount; $i++) {
    		$oSingle = New-Object -TypeName System.Management.Automation.PSObject
    		Add-Member -InputObject $oSingle -MemberType NoteProperty -Name Date -Value $null   # String
    		Add-Member -InputObject $oSingle -MemberType NoteProperty -Name Time -Value $null   # String
    		Add-Member -InputObject $oSingle -MemberType NoteProperty -Name Timestamp -Value $null   # Datetime
    		Add-Member -InputObject $oSingle -MemberType NoteProperty -Name GMTTimestamp -Value $null   # Datetime
    		Add-Member -InputObject $oSingle -MemberType NoteProperty -Name ThreadID -Value $null
    		Add-Member -InputObject $oSingle -MemberType NoteProperty -Name Context -Value $null
    		Add-Member -InputObject $oSingle -MemberType NoteProperty -Name PacketID -Value $null
    		Add-Member -InputObject $oSingle -MemberType NoteProperty -Name IPType -Value $null
    		Add-Member -InputObject $oSingle -MemberType NoteProperty -Name SndOrRcv -Value $null
    		Add-Member -InputObject $oSingle -MemberType NoteProperty -Name RemoteIP -Value $null
    		Add-Member -InputObject $oSingle -MemberType NoteProperty -Name XID -Value $null
    		Add-Member -InputObject $oSingle -MemberType NoteProperty -Name QueryOrResponse -Value $null
    		Add-Member -InputObject $oSingle -MemberType NoteProperty -Name OpCode -Value $null
    		Add-Member -InputObject $oSingle -MemberType NoteProperty -Name Flags -Value $null
    		Add-Member -InputObject $oSingle -MemberType NoteProperty -Name FlagsCharCode -Value $null
    		Add-Member -InputObject $oSingle -MemberType NoteProperty -Name ResponseCode -Value $null
    		Add-Member -InputObject $oSingle -MemberType NoteProperty -Name QuestionType -Value $null
    		Add-Member -InputObject $oSingle -MemberType NoteProperty -Name QuestionName -Value $null
    		Add-Member -InputObject $oSingle -MemberType NoteProperty -Name PSComputerName $null
    		Add-Member -InputObject $oSingle -MemberType NoteProperty -Name GMTOffset_PSComputer $null
    		Add-Member -InputObject $oSingle -MemberType NoteProperty -Name DnsServerName -Value $null
    		$aReturned += $oSingle
    	}
        return ,$aReturned
    }
    function Create-ReqRespLineRegex() {
    	# Create a regex object for a normal DNS Packet Debug Log line
        # http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
        # Works on these types of lines:
        # 4/26/2016 8:45:38 AM 0B4C PACKET  0000000002706310 UDP Rcv 10.100.0.53    f055   Q [0001   D   NOERROR] A      (12)mrk-325-srv3(8)mydomain(3)com(0)
        # 4/26/2016 8:46:05 AM 0B4C PACKET  0000000002FD4B90 UDP Rcv 10.100.8.234    6cb6   Q [0001   D   NOERROR] PTR    (3)233(1)8(3)104(2)10(7)in-addr(4)arpa(0)
        # 4/26/2016 8:48:23 AM 0B4C PACKET  000000000263B4B0 UDP Rcv 172.16.1.250    3ebb   Q [0005 A D   NOERROR] A      (12)mrk-bus-srv3(9)mydomain1(3)com(0)
        # 4/26/2016 8:47:22 AM 0B4C PACKET  0000000006F6F860 UDP Rcv 172.16.1.250    b72d   Q [0005 A D   NOERROR] NS     (7)webmail(9)mydomain1(3)com(0)
        # 4/27/2016 8:21:53 AM 0B4C PACKET  00000000025597A0 UDP Rcv 10.7.0.20       61dc   Q [0201   D  SERVFAIL] A      (3)api(8)chatgame(2)me(0)
        # 4/27/2016 3:51:33 AM 0B4C PACKET  0000000002621DD0 UDP Rcv 10.104.8.54     009c   Q [1000       NOERROR]          <<<< What is this?
        $arrRegPrep = @()
    	$arrRegPrep += "(?<Date>^\d{1,2}\/\d{1,2}\/\d{4})"   # 4/26/2016
        $arrRegPrep += "(?<G1>\s)"  # Garbage
        $arrRegPrep += "(?<Time>\d{1,2}\:\d{1,2}\:\d{1,2}\s[AP]M)" # 8:53:56 PM
        $arrRegPrep += "(?<G1>\s)"  # Garbage
        $arrRegPrep += "(?<ThreadID>\S{3,4})"
        $arrRegPrep += "(?<G1>\s)"  # Garbage
        $arrRegPrep += "(?<Context>PACKET)"
        $arrRegPrep += "(?<G1>\s*)"  # Garbage
        $arrRegPrep += "(?<PacketID>[0-9A-Za-z]{8,16})" # 0000000003A91570
        $arrRegPrep += "(?<G1>\s)"  # Garbage
        $arrRegPrep += "(?<IPType>TCP|UDP)" # TCP or UDP
        $arrRegPrep += "(?<G1>\s)"  # Garbage
        $arrRegPrep += "(?<SndOrRcv>Snd|Rcv)" # Snd or Rcv
        $arrRegPrep += "(?<G1>\s)"  # Garbage
        $arrRegPrep += "(?<RemoteIP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-f,0-9,:]{3,39})" # IPV4 or IPv6.  IPv6 min is "::1", max is 39 chars
        $arrRegPrep += "(?<G1>\s*)"  # Garbage
        $arrRegPrep += "(?<XID>\S{4})" # Hex
        $arrRegPrep += "(?<G1>\s)"  # Garbage
        $arrRegPrep += "(?<QueryOrResponse>(\s{1}|R))" # ' '=Query or 'R'=Response
        $arrRegPrep += "(?<G1>\s)"  # Garbage
        $arrRegPrep += "(?<OpCode>Q|N|U|\?)" # Opcode Q=Standard Query, N=Notify, U=Update, ?=Unknown
        $arrRegPrep += "(?<G1>\s*\[)(?<Flags>\S{4})(?<G1>\s)(?<FlagsCharCode>[\sATDR]{3,5})(?<G1>\s)(?<ResponseCode>\w*)(?<G1>\])"
        $arrRegPrep += "(?<G1>\s)"  # Garbage
        #$arrRegPrep += "(?<QuestionType>A|SRV|PTR|MX|NS|AAAA|SOA|CNAME|IXFR|TXT)"
        $arrRegPrep += "(?<QuestionType>\S{1,10})"
        $arrRegPrep += "(?<G1>\s*)"  # Garbage
        $arrRegPrep += "(?<QuestionName>\(.*)"
        # Use .NET regex as it should be faster
        $regLine = [regex] ($arrRegPrep -join '')
        return $regLine
    }
    function Parse-DNSDebugLogLineToObject( 
    	[Parameter(Mandatory=$true)] [array] $aLines,
    	[Parameter(Mandatory=$true)] [regex] $regLine
        ) {
    	# Parse a DNS Debug Log line
    	# Input:   Array of strings, one cell per line of text
        #          Regular expression to match to a single line
        # Also:    Needs $regQParSep='(\(\d{1,3}\))' $sPSComputerName, $sPSComputerTzOffset, $sDnsServerFQName defined outside this function
    	# Returns: Pipeline of custom DNS Query objects that match the regex
    	$aLines | ForEach-Object {
            if ( $_.Length -eq 0 ) {
                return # Break to next object in pipeline
            }
    		$Matches = $null
    		if ( $_ -match $regLine ) {
                if ( $Matches.QuestionType.Trim() -in $IgnoreQryType ) {
                    # Ignore this query type
                    return # Break to next object in pipeline
                }
    			$oSingle = (DNSLogEntryFactory)[0]
    			$oSingle.Date = $Matches.Date.Trim()
                $oSingle.Time = $Matches.Time.Trim()
                $oSingle.Timestamp = [datetime] ($oSingle.Date+" "+$oSingle.Time)
                # Next line does NOT account for 30min offset countries!!!
                $oSingle.GMTTimestamp = $oSingle.Timestamp.AddMinutes(([int] $DnsServerTzOffset)*-60) # Need inverse number so we end up at GMT.  
                $oSingle.ThreadID = $Matches.ThreadID.Trim()
                $oSingle.Context = $Matches.Context.Trim()
                $oSingle.PacketID = $Matches.PacketID.Trim()
                $oSingle.IPType = $Matches.IPType.Trim()
                $oSingle.SndOrRcv = $Matches.SndOrRcv.Trim()
                $oSingle.RemoteIP = $Matches.RemoteIP.Trim() # [ipaddress] $Matches.RemoteIP.Trim()
                $oSingle.XID = $Matches.XID.Trim()
                $oSingle.QueryOrResponse = $htQRLookup[$Matches.QueryOrResponse] # Cannot trim because " "=Query
                $oSingle.OpCode = $htOpCodeLookup[$Matches.OpCode.Trim()]
                $oSingle.Flags = $Matches.Flags.Trim()
                # Change single character flags to descriptions
                $sFlagsCharCode = $Matches.FlagsCharCode.Replace(' ','')
                $sFlagsCharCodeDesc = ''
                $iCount = $sFlagsCharCode.Length
                for ($i = 0; $i -lt $iCount; $i++) {
                	$sFlagsCharCodeDesc = $sFlagsCharCodeDesc + $htFlagsCharCodeLookup[$sFlagsCharCode[$i]] + ', '
                }
                $oSingle.FlagsCharCode = $sFlagsCharCodeDesc.TrimEnd(', ')
                $oSingle.ResponseCode = $Matches.ResponseCode.Trim()
                $oSingle.QuestionType = $Matches.QuestionType.Trim()
                $oSingle.QuestionName = ($Matches.QuestionName.Trim() -replace $regQParSep,'.').Trim('.') # Sub in periods and trim ends.
    			$oSingle.PSComputerName = $sPSComputerName
                $oSingle.GMTOffset_PSComputer = $sPSComputerTzOffset
                $oSingle.DnsServerName = $sDnsServerFQName
                $oSingle
    		}
            else {
                Out-Null
                $sTextOut = 'Invalid parsed line: '+$_.ToString()
                Write-Debug $sTextOut       # Use this to view output:  $DebugPreference = 'Continue'
            }
    	}
    } # End Parse-DNSDebugLogLineToObject
    function Wait-ForFileCreation([int] $iTotalLoops, [int] $iSecPause, [string] $sFilePath) {
        for ($i = 0; $i -lt $iTotalLoops; $i++) {
            if ( Test-Path $sFilePath ) {
                break
            }
        	Start-Sleep $iSecPause
        }
    }
    $regLine1 = Create-ReqRespLineRegex
    $regQParSep = [regex] '(\(\d{1,3}\))' # Looking for '(5)' that separage the subdomain strings
} # End Begin section
Process {
    if (($null -eq $DnsServerName) -or ($DnsServerName -eq '') -or ($DnsServerName -eq '.')) {
        # Try to get the DNS server name automatically.  Cannot assume the file being processed is still on the DNS server
        if ($DnsDebugLogFilePath -eq ($env:windir+'\system32\dns\dns.log')) {
            $oComputer = Get-WmiObject Win32_ComputerSystem
            $sDnsServerFQName = ($oComputer.Name+'.'+$oComputer.Domain).ToLower()
        }
        else {
            throw 'Unable to get DnsServerName.  Please pass in a fully qualified name.'
        }
    }
    else {
        $sDnsServerFQName = $DnsServerName.ToLower()
    }
    $sPSComputerName = (Get-WmiObject Win32_ComputerSystem).Name
    $sPSComputerTzOffset = (Get-Date -UFormat %Z) # String +/-00 from GMT
    # Try to automatically get the DNS server timezone offset
    if ($sDnsServerFQName.Contains($sPSComputerName)) {
        # Name is the same so use the same TZ
        $DnsServerTzOffset = $sPSComputerTzOffset
    }
    else {
        if ($DnsServerTzOffset -eq '') {
            throw 'Unable to get DnsServerTzOffset.  Please pass in a string of the timezone offset.'
        }
        # Nothing to be done for else because the timezone is already set
    }
    Write-Verbose "Reading contents of $DNSDebugLogFilePath"
    if ( $t ) { # Tail the file one line at a time.  
        # The out While loop is to restart reading on the file recreation.
        # The Get-Content processing is realtime so its loop never ends.
        # The -Tail 0 means read the 0 lines of the file, it is a silent startup.
        #Wait-ForFileCreation 40 5 $DNSDebugLogFilePath   # Use when the server is starting, 120 seconds total
        $bolLoop = $true
        while ($bolLoop) {
            Try {
                Get-Content $DNSDebugLogFilePath -Tail 0 -Wait -ErrorAction Stop | ForEach-Object {
                    Parse-DNSDebugLogLineToObject @($_) $regLine1
                }
            }
            Catch [Exception] {
                $err = $_
                switch ($err.FullyQualifiedErrorId.ToString()) {
                	'GetContentReaderIOError,Microsoft.PowerShell.Commands.GetContentCommand' {
                		# File is changed while we are watching it.  Failure to initially 
                        # read the file is a different type of error from this one.
                        # Wait 5 Seconds for file to be recreated
                        Wait-ForFileCreation 5 1 $DnsDebugLogFilePath 
                		break
                	}
                	default {
                        $bolLoop = $false
                        $sDesc = $err.Exception.Message.ToString()
                        $eventLog.WriteEntry($sDesc,$eventType,$eventID)
                        throw $err
                		break
                	}
                }
            }
        }
    }
    else { # Read entire file
        Get-Content $DNSDebugLogFilePath | ForEach-Object {
            Parse-DNSDebugLogLineToObject @($_) $regLine1
        }
    }
} # End Process section
} # End Get-DnsDebugLogLineToObject

function Start-Get-DnsDebugLogLineToObject() {
    # This contents can go in some other script and passed to the Get-DnsDebugLogLineToObject function
    #$DnsDebugLogFilePath = $env:windir+'\system32\dns\dns.log'
    $DnsDebugLogFilePath = 'C:\Windows\System32\dns\dns.log'
    $DnsServerName = '.' # Fully Qualified Domain Name, use '.' to indicate local machine 
    $DnsServerTzOffset = (Get-Date -UFormat %Z) # Optional, String +/-00 from GMT
    $IgnoreQryType = @('PTR')
    Get-DnsDebugLogLineToObject -DnsDebugLogFilePath $DnsDebugLogFilePath -DnsServerName $DnsServerName `
                                 -DnsServerTzOffset $DnsServerTzOffset -IgnoreQryType $IgnoreQryType -t
}

Start-Get-DnsDebugLogLineToObject
