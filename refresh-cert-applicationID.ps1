#gathers a list of all the IP's that have ports with certificates attached to them
$oldIPs = netsh http show sslcert | select-string -Pattern 'IP:port' | foreach-object {$a,$b = ([string]$_).split(":")[2..3]; "$a.$b" } 
$oldIPs = $oldIPs.trim()
$oldIPs = $oldIPs.separate('"',"")

#the loop gathers info on each ip listed, and substitutes the certificate currently active for the latest one that share the same name
foreach ($oldIP in $oldIPs) {
    #gathers the info on the thumbprint of the certificate based on the port its attached to
    $oldcerthash = netsh http show sslcert $oldIP | select-string -Pattern 'Certificate Hash' | foreach-object { ([string]$_).split(":")[1] }
    $oldcerthash = $oldcerthash.trim()

    #gets the certificate name based on the thumbprint of the currently attached certificate to the port
    $oldcertname = get-childitem -path cert:\localmachine\my | where-object {($_.thumbprint -eq $oldcerthash)} |select-object subject -expandproperty "subject"

    #gets the appID thats currently attached to the port
    $appID = netsh http show sslcert $oldIP | select-string -Pattern 'Application ID' | foreach-object { ([string]$_).split(":")[1] }
    $appID = $appID.trim()

    #checks the latest certificate that shares the name with the current one installed in the port
    $newcerthash = get-childitem -path cert:\localmachine\my | where-object {($_.subject -eq $oldcertname)} | sort-object -property notafter -descending | select-object thumbprint -first 1 -expandproperty "thumbprint"

    if($NULL -eq $newcerthash){
        continue;
    }
    else {
        netsh http delete sslcert $oldIP
        netsh http add sslcert ipport=$oldIP certhash=$newcerthash appid="$appID"
    }
    #due to conflicts between how CMD and powershell parses commands, the appid= value needs to be put inside double quotes, or else powershell will not be able to parse the command, with "", the command will work on both CMD and powershell
}

#you can add extra filters to the $newcerthash variable if you need a more granular control, for example
#-and $($_.issuer -match "specific CA")
#-and $($_.notbefore -t (getdate).AddDays(-whatever))