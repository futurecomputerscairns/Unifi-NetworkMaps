if (Get-Module -ListAvailable -Name PSWriteHTML) {
    Import-Module PSWriteHTML
} 
else {
    Install-Module PSWriteHTML -Force
    Import-Module PSWriteHTML
}



if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
 }
[ServerCertificateValidationCallback]::Ignore()

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
 
# UniFi Details
$UnifiBaseUri = "https://[IP or FQDN here]:8443"
$UnifiCredentials = @{
    username = "[Unifi Username here]"
    password = "[Unifi Password here]"
    remember = $true
} | ConvertTo-Json
 
$UnifiBaseUri = "$UnifiBaseUri/api"
$credentials = $UnifiCredentials
 
Invoke-RestMethod -Uri "$UnifiBaseUri/login" -Method POST -Body $credentials -SessionVariable websession
 
# Get Sites
$sites = (Invoke-RestMethod -Uri "$UnifiBaseUri/self/sites" -WebSession $websession).data

foreach ($site in $sites){
 
# all devices

$unifiDevices = Invoke-RestMethod -Uri "$UnifiBaseUri/s/$($site.name)/stat/device" -WebSession $websession

#access points

$UAPs = $unifiDevices.data | Where-Object {$_.type -contains "uap"}

$Accesspoints = @()
foreach ($UAP in $UAPs){
                
                
                $object = New-Object psobject
                $object | Add-Member -MemberType NoteProperty -Name APName -Value $UAP.name
                $object | Add-Member -MemberType NoteProperty -Name APIP -Value $UAP.ip
                $object | Add-Member -MemberType NoteProperty -Name APMAC -Value $UAP.mac
                $object | Add-Member -MemberType NoteProperty -Name APUplink -Value $UAP.last_uplink.uplink_mac

                $Accesspoints += $object
}

#switches

$USWs = $unifiDevices.data | Where-Object {$_.type -contains "usw"}
$switches = @()
foreach ($USW in $USWs){
                
                
                $object = New-Object psobject
                $object | Add-Member -MemberType NoteProperty -Name SwitchName -Value $USW.name
                $object | Add-Member -MemberType NoteProperty -Name SwitchIP -Value $USW.ip
                $object | Add-Member -MemberType NoteProperty -Name SwitchMAC -Value $USW.mac

                $switches += $object
}

#USG

$USG = $unifiDevices.data | Where-Object {$_.type -contains "ugw"}



# currently connected users

$users = Invoke-RestMethod -Uri "$UnifiBaseUri/s/$($site.name)/stat/sta" -WebSession $websession

$wifi = Invoke-RestMethod -Uri "$UnifiBaseUri/s/$($site.name)/rest/wlanconf" -WebSession $websession

# Is connected via LAN

$LANUsers = $users.data | Where-Object {$_.'is_wired' -contains 'False'}

# Connected to which switch (by MAC)

#$LANUsers.sw_mac

# Is connected via WLAN

$wirelessusers = $users.data | Where-Object {$_.'is_wired' -notcontains 'False'}

# connected to which switch (by MAC)

#$wirelessusers.ap_mac
$Reportpath = 'C:\temp\NetworkMaps\' + ($Site.desc -replace ' ', '') + '-Network-Report.html' 
New-HTML -TitleText ($site.desc + ' Network Map' | Out-String) -Encoding UTF8 -UseCssLinks -UseJavaScriptLinks -FilePath $Reportpath {
    New-HTMLDiagram -Height '1500px' {
        New-DiagramOptionsInteraction -Hover $true
        New-DiagramNode -Label ($USG.name | Out-String) -Image 'https://theme.zdassets.com/theme_assets/77613/ff7ff89edfceb228b54443702ffba57c08d686fc.png'
        foreach ($switch in $switches){
        New-DiagramNode -Label ($switch.Switchname | Out-String) -To ($USG.name | Out-String) -Image 'https://theme.zdassets.com/theme_assets/77613/ff7ff89edfceb228b54443702ffba57c08d686fc.png'
        }
        foreach ($Accesspoint in $Accesspoints){
        $matchingswitch = $switches | Where-Object {$_.SwitchMAC -contains $Accesspoint.APUplink}
        New-DiagramNode -Label ($Accesspoint.APname | Out-String) -To ($Switch.SwitchName | Out-String) -Image 'https://theme.zdassets.com/theme_assets/77613/ff7ff89edfceb228b54443702ffba57c08d686fc.png'
        }
        foreach ($user in $users.data){
        $matchingswitch = $null
        $matchingswitch = $switches | Where-Object {$_.SwitchMAC -contains $user.sw_mac} | Select -First 1
        if ($null -ne $matchingswitch){
        New-DiagramNode -Label ($User.hostname + ' - ' + $User.mac | Out-String) -To ($matchingswitch.SwitchName | Out-String) -Image 'https://image.flaticon.com/icons/svg/1674/1674840.svg'
        }
        $matchingAP = $null
        $matchingAP = $Accesspoints | Where-Object {$_.APMAC -contains $user.ap_mac} | Select -First 1
        if ($null -ne $matchingAP){
        New-DiagramNode -Label ($User.hostname + ' - ' + $user.essid | Out-String) -To ($matchingAP.APname | Out-String) -Image 'https://image.flaticon.com/icons/svg/159/159599.svg'
        }
        }
    } #-BundleImages
} -Verbose 

}