# Firewall Block Script
# This script will scan firewall log, and check any attempt on 3389 and will determine whether the
# remote desktop connection request is a valid request or not?
#
# The way to identified it is to ensure that if this is coming from remote, it should have 2 connection
# with only 1 port differences on the source port.

# get the common configuration
$dt = Get-Date -UFormat "%Y%m%d-%H%s"
$path = "C:\scripts\firewall_block-"+$dt+".txt"

# change this if you want to strict or loosen the checkn
$maxTries = 3

# start transcript the Power Shell output
Start-Transcript -Path $path

$hash = @{}
$srcHash = @{}

# get the firewall rule and remote address that already registered on the firewall rule
$fwr = Get-NetFirewallRule -DisplayName "BlockAttackerToWindows" | Get-NetFirewallAddressFilter
[string[]]$ra = $fwr.RemoteAddress

# loop thru all remote address found in firewall rule to build the source hash.
# this source hash will be used to check if the current ip address that we detected on the
# firewall log, already listed on the remote address at the firewall rule or not?
# to ensure that we will not adding duplicate IP address in the rule.
# (in case someone try 250 times, we don't want that 250 same ip address add on the firewall rule)
foreach($era in $ra) {
    $ip_era = $era.split("/",[System.StringSplitOptions]::RemoveEmptyEntries)
    $srcHash.Add($ip_era[0],"blocked")
}

Write-Host ════════════════════════════════════════════════════════════════════════════════
Write-Host [⏳] Open EventLog for 1 day before

# Open event log viewer to get the event id 4625
Get-EventLog security -After (Get-Date).AddHours(-24) | where {$_.EventID -eq 4625} | ForEach-Object {
   # Get the event viewer message and time of event
   $msg = $_.Message
   $eventTime = $_.TimeGenerated

   # try to find if there are Source Network Address that will pinpoint the remote address that
   # being used to access the RDP
   $rmtLocation = $msg.IndexOf("Source Network Address:");
   $rmtLocation = $rmtLocation + 24;
   $rmtEOF = $msg.IndexOf("`n", $rmtLocation);
   #Write-Host $rmtLocation and $rmtEOF

   # once we got the location, ensure that the end of the remote address is greater than the
   # start position, if so we can try to substring the event message to get the source network
   # address of the perpeptuator
   if($rmtEOF -gt $rmtLocation) {
      $rmtLen = $rmtEOF - $rmtLocation

      # ip address minimum length is 7, so lesser than this we just skip the data
      if($rmtLen -gt 7) {
         # get the actual remote ip address
         $rmtData = $msg.Substring($rmtLocation,$rmtLen);
         
         # add to hash table
         $dot = $rmtData.LastIndexOf('.')
         $rmtDataSegment = $rmtData.Substring(0,$dot)

         # check whether this is a local segment or not?
         if($rmtDataSegment -eq "192.168.1") {
            Write-Host [ℹ] $rmtDataSegment is local machine no need to block
         }
         else {
            # not local segment, if so add .0 at the end of the remote ip address since
            # we plan to blocked segment C of the remote ip address to ensure that
            # they cannot perform any attack if their ip address is change
            $rmtDataBlockedIp = $rmtDataSegment+".0"

            # check if we already have this remote ip address in our hash table or not?
            if($hash.ContainsKey($rmtDataBlockedIp)) {
               # hash table already exists, it means we can just add how many attempts that
               # this person do to the machine
               $currHash = $hash[$rmtDataBlockedIp]
               $currHash = $currHash + 1
               $hash[$rmtDataBlockedIp] = $currHash
               # Write-Host [➕] $currHash attempts for $blockedIP
            }
            else {
               # if not exists yet in our hash table, then add the remote ip address in the hash table
               $hash.add($rmtDataBlockedIp, 1)
               Write-Host [⚠] Failed Login Attempt from $rmtDataBlockedIp at $eventTime
            }
         }
      }
      else {
         # the data is skipped, since the source network address that we got is less than 7
         Write-Host [ℹ] Skip data for $msg.Substring($rmtLocation,$rmtLen);
      }
   }
}
# scanning of the event log is finished
Write-Host [✔] Finished Scanning
Write-Host ════════════════════════════════════════════════════════════════════════════════

Write-Host [⏳] Start Processing
try {
   # now loop from all the hash table that we generated above that contain list of blocked
   # IP address based on the firewall log.
   foreach($h in $hash.GetEnumerator()) {
      # check if this is already in source hash or not?
      if($srcHash.ContainsKey($h.name)) {
         Write-Host [🔎] $h.name with $h.value failed attempts, already in the Firewall
      }
      else {
         # check how many attempt that it try
         # if < $maxTries then no need to block
         if($h.value -gt $maxTries) {
             $blockIPSegment = $h.name + "/255.255.255.0"
             $ra += $blockIPSegment
             Write-Host [🛑] Add $h.name in Blocked List with $h.value Attempts
         }
      }
   }

   #set new address filter
   $fwr | Set-NetFirewallAddressFilter -RemoteAddress $ra -ErrorAction Stop
}
catch {
   $PSCmdlet.ThrowTerminatingError($PSitem)
}
Write-Host [✔] Finished Processing
Write-Host ════════════════════════════════════════════════════════════════════════════════

# script done!
Stop-Transcript
