# Block Failed RDP Attempts
Block the failed RDP attempts (event id 4625) to windows machine using Powershell.

Someone is trying to keep login on my Windows 10 remote desktop, and eventually lock out my ID, looking for fail2ban solution, but seems there are no free solution available to do the same job as fail2ban, so I opt to create one instead.

# What Do I need to Prepare

Create one Windows Firewall rule to block all the incoming connection with name "BlockAttackerToWindows".
All the remote IP address will put on the remote IP address section of this Firewall profile. You can change the profile name that being used, by editing the PowerShell script when it add the policies to the Firewall.

All this script need elevated privilege, as accessing Security Event Log Viewer, and Set Firewall Rule is restricted using non-elevated account.

# Can I put it as Schedule Task

Of course you can, you can create as Task Schedule that will trigger the script everytime system detect there are event ID 4625 occured in your event viewer log, or you can just run it daily at certain time, by default the script will check 24 hours prior to current date and time on the event viewer log.

Don't forget to run the Task Schedule as high level to ensure that it got the elevated rights to run the power shell command.
