## Kaspersky Threat Feed   
  https://tip.kaspersky.com/

### Overview
Kaspersky Threat Feed Service for DNIF is an enrichment plugin that allows you to check URLs, file hashes, and IP addresses contained in events that arrive in a SIEM software product.   
The URLs, file hashes, and IP addresses are checked against data feeds from Kaspersky Lab.  
Categories of these objects are determined during the matching process.

### PRE-REQUISITES to use  Kaspersky Threat Feed API and DNIF  

- PEM certificate received from your dedicated Kaspersky Lab Technical Account Manager

- Outbound access required to clone the Kaspersky enrichment plugin 

| Protocol   | Source IP  | Source Port  | Direction	 | Destination Domain | Destination Port  |  
|:------------- |:-------------|:-------------|:-------------|:-------------|:-------------|  
| TCP | AD,A10 | Any | Egress	| github.com | 443 |
| TCP | AD,A10 | Any | Egress	| wlinfo.kaspersky.com | 443 |   

   

### Using the Kaspersky Threat Feed API with DNIF
 The  Kaspersky Threat Feed API is found on github at

https://github.com/dnif/enrich-kaspersky

### Getting started with Kaspersky Threat Feed  API

1. ####    Login to your AD, A10 containers  
   ACCESS DNIF CONTAINER VIA SSH : [Click To Know How](https://dnif.it/docs/guides/tutorials/access-dnif-container-via-ssh.html)
2. ####    Move to the ‘/dnif/<Deployment-key/enrichment_plugin’ folder path.
```
$cd /dnif/CnxxxxxxxxxxxxV8/enrichment_plugin/
```
3. ####   Clone using the following command  
```  
git clone https://github.com/dnif/enrich-kaspersky.git kaspersky
```
### Kaspersky Threat Feed API feed output structure
The output of the enrichment has the following structure (for the available data):

  | Fields        | Description  |
| ------------- |:-------------:|
| EvtType      | An Domain |
| EvtName      | The IOC      |
| IntelRef | Feed Name      |
| IntelRefURL | Feed URL    |
| ThreatType | DNIF Feed Identification Name |      
| KLMD5 | List of MD5 observed for the IOC  |
| KLSHA1  | List of SHA1 observed for the IOC  |
| KLSHA256  | List of SHA1 observed for the IOC  |
| KLThreatDetail  | More details of the threat  |
| KLGeo  | Geo locations present against the IOC in Kaspersky database  |
| KLIP  | List of IP addresses that have been associated with the IOC  |
| KLPopularity  | Popularity of the IOC with Kaspersky |
| KLIndustry  | Targeted Industry of the IOC |

The API also returns WHOIS information for IOC as and when present as follows

| KLRegistrarName  | Registry name present in WHOIS record | 
| KLCity  | City details present in WHOIS record |
| KLCountry  | Country details present in WHOIS record |
| KLCreated  | Creation date of the domain present in WHOIS record |
| KLExpires | Expiry date of the domain present in WHOIS record |
| KLUpdated  | Updated date of the domain present in WHOIS record |  

An example of Kaspersky Threat Feed output
```
{
'EvtName': u'cgaemihcbvr.com',
'EvtType': 'DOMAIN'
'AddFields': {'IntelRef': ['KASPERSKY'],
               'IntelRefURL': [],
               'KLCity': ['Panama'],
               'KLCountry': ['PANAMA'],
               'KLCreated': ['20.09.2018'],
               'KLDomain': ['cgaemihcbvr.com'],
               'KLEmail': ['1d60a94329c2427e8ab82be3a2d275f0.protect@whoisguard.com'],
               'KLExpires': ['20.09.2019'],
               'KLGeo': ['de',
                         ' it',
                         ' gb',
                         ' es',
                         ' dz',
                         ' in',
                         ' sa',
                         ' fr',
                         ' us',
                         ' ru'],
               'KLIP': ['178.62.208.24',
                        ' 104.236.233.182',
                        ' 185.28.191.30',
                        ' 77.111.247.74',
                        ' 178.62.43.135',
                        ' 192.230.35.70',
                        ' 80.240.128.221',
                        ' 54.37.73.125',
                        ' 5.254.65.15',
                        ' 128.199.75.236'],
               'KLMD5': [u'701ED86D5F9A5B4E8188AA6DEB964DAD',
                         u'401EF58C34445AFEB9CCC07EC0DD9BA1',
                         u'8DBB5E3E7F6F0B18BB5B64AA1C040567'],
               'KLName': ['WhoisGuard Protected'],
               'KLNs': ['ns0.dnsmadeeasy.com',
                        ' ns1.dnsmadeeasy.com',
                        ' ns2.dnsmadeeasy.com',
                        ' ns3.dnsmadeeasy.com',
                        ' ns4.dnsmadeeasy.com'],
               'KLOrg': ['WhoisGuard', ' Inc.'],
               'KLPopularity': [5],
               'KLRegistrarName': ['NameCheap Inc.'],
               'KLSHA1': [u'BDFDFAA2DAD8D37F57BD5E525D7F60EFDE456265AF2FBC93535A12D3954AF276',
                          u'DFD8AFA96A4BAC4E09D11E73A04B4147CBDFBF9CBC5F20C51B20E4BAC7007B75',
                          u'9643B0F53EE98C6247B119DCB16C86388E663694B10949164B768AF7E679B19A'],
               'KLSHA256': [u'B36577581DECDBCEF3B318D751F30CD94D46633F'],
               'KLThreatDetail': [u'HEUR:Trojan.Script.Miner.gen'],
               'KLUpdated': ['20.09.2018'],
               'ThreatType': ['MALWARE']},
 }
```
