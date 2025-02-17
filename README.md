# Azure_HoneyPot
Azure-hosted Sentinel SIEM Log Analysis, Configuration and KQL Querying<hr>
Scope: Create a VM honeypot on the cloud, query, and analyze logs on Sentinel.<hr>

Architecture: Resource group -> Virtual Network -> Subnet -> VM Honeypot -> Log Analysis Workspace (Central Log Repository) -> Sentinel SIEM -> Geographic Information Watchlist.<hr> 

1. Setup Azure Subscription

Create Free Azure Account: https://azure.microsoft.com/en-us/pricing/purchase-options/azure-account

Login with your credentials at:
https://portal.azure.com


2. Create Azure VM Honeypot

Go to: https://portal.azure.com and search for virtual machines

Create a new Windows 10 virtual machine  

Go to the Network Security Group for your virtual machine and create a rule that allows all traffic inbound

Log into your virtual machine and turn off the windows firewall (start -> wf.msc -> properties -> all off)


3. Log into the VM Honeypot and inspect logs

On purpose fail a few logins to your VM


Login to your virtual machine

Go to Event Viewer -> Windows Logs -> Security to inspect the security logs

Locate failed login attempts, event ID should be 4625
 

4. Log Forwarding and KQL

Go to portal.azure.com -> Home -> Log Analytics Workspaces to create a central log repository


Create a Sentinel Instance and connect it to Log Analytics

Configure the “Windows Security Events via AMA” connector

Create the Data Collection Rules in Sentinel, watch for extension creation

Query for logs within the LAW

Observe some of your VM logs:

SecurityEvent
| where EventId == 4625


5. Log Enrichment and Finding Location Data

Observe the SecurityEvent logs in the Log Analytics Workspace; there is no location data, only IP address, which we can use to derive the location data.

We are going to import a spreadsheet (as a “Sentinel Watchlist”) which contains geographic information for each block of IP addresses.

Download: geoip-summarized.csv at https://drive.google.com/file/d/13EfjM_4BohrmaxqXZLB5VUBIz2sv9Siz/view

Within Sentinel, create the watchlist:

Name/Alias: geoip
Source type: Local File
Number of lines before row: 0
Search Key: network

Allow the watchlist to fully import, there should be a total of about 55,000 rows.

In real life, this location data would come from a live source or it would be updated automatically on the back end by your service provider.

(observe architecture)

Observe the logs now have geographic information, so you can see where the attacks are coming from

let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == <attacker IP address>
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents


(observe architecture)

6. Attack Map Creation

Within Sentinel, create a new Workbook

Delete the pre populated elements and add a “Query” element

Go to the advanced editor tab, and paste the JSON

Workbook (Attack map):
map.json https://drive.google.com/file/d/1ErlVEK5cQjpGyOcu4T02xYy7F31dWuir/view

Observe the query</br>
Observe the map settings </br>
Observe the map</br>


Based on a tutorial by Josh Madakor, some steps are original, some are modified and explained according to my understanding of the topic.


