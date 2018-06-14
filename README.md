## WEBROOT BRIGHTCLOUD® THREAT INTELLIGENCE   
 https://www.webroot.com/us/en/business/threat-intelligence

### Overview

Webroot is the largest privately held internet security organisation based in the United States operating globally across North America, Europe and the Asia Pacific region.Webroots BrightCloud Service helps network and security vendors augment their customers security by adding a dynamic service to their defenses.  

The BrightCloud Service is powered by the Webroot® Threat Intelligence Platform, which uses a big data architecture to provide the most comprehensive and accurate threat intelligence available today, including up-to-the-minute intelligence on IPs of emerging threats.This intelligence can be used to block traffic from TOR nodes, proxies, botnets, and other malicious actors.The service also provides information such as historical and geolocation data to help security admins make better threat decisions.   
Webroot® BrightCloud Security Services include the following catagories
##### Web Classifications
Provides content classification for billions of webpages to keep users safe from online threats

##### Web Reputation
Forecasts the security risk of visiting a website and enables administrators to finely tune security settings 

##### IP Reputation
Publish dynamic intelligence of high-risk IP addresses and insight into inbound and outbound communications

##### File Reputation
Provides dynamic file reputation intelligence of known malicious and whitelisted files to stop the distribution of malware



##### Lookups integrated with WEBROOT BRIGHTCLOUD® THREAT INTELLIGENCE

### Note 
Reputation score classification for URL

|Score Range       | Description  |
|:------------- |:-------------|
|  1 - 20 | High Risk |
| 21 – 40 | Suspicious |
| 41 – 60 | Moderate Risk |
| 61 – 80 | Low Risk |
| 81 – 100 | Trustworthy |

Popularity classification for URL

|Popularity        | Description  |
|:------------- |:-------------|
| 1  | Site ranking is in top 100,000 sites |
| 2  | Site ranking is in top 1 million sites |
| 3  | Site ranking is in top 10 million sites |
| 4  | Site ranking lower than top 10 million sites |
| 5  | TUnranked site |

##### Retrieve URL information  
This endpoint returns content classification and reputation information on the queried URL.
- input : A URL for which you want to retrieve information.        
```
_fetch $Url from threatsample limit 1
>>_lookup webroot get_url_info $Url
```
###### Sample Output 
![get_urlinfo](https://user-images.githubusercontent.com/37173181/40767527-65864d5c-64d0-11e8-8883-62996b6dc470.jpg)

The Lookup call returns output in the following structure for available data

  | Fields        | Description  |
|:------------- |:-------------|
| $BCTIa1cat      | A value of a1cat = 1 indicates that the entire authority (all paths) are of the same category.This enables more efficient caching. |
| $BCTIReputation      | Reputation score for the queried URL (Refer to notes section for details on score classification) |
| $BCTILCP | Least common part |
| $BCTICategoryId | A positive integer number representing the category Id |
| $BCTICategoryconfidence | Confidence score the category assigned to this URL |
| $BCTIAPIStatus | Returns the API status code of the request made |

#####  Retrieve reputation information of URL:
This endpoint returns extended reputation information of URLs, for example: country, popularity,age, etc.
- input : A URL for which you want to retrieve information.

```
_fetch $Url from threatsample limit 1
>>_lookup webroot get_url_repinfo $Url
```

##### Sample Output 
![get_urlrepinfo](https://user-images.githubusercontent.com/37173181/41393970-bed98e50-6fc5-11e8-9cde-651451da9b41.jpg)

The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $BCTIAge      | Number of months that BrightCloud has known about this authority. |
| $BCTICountry | Two letter country ID |
| $BCTIPopularity | Popularity category of the URL (refer to notes section for details on popularity classification)  |
| $BCTIReputation | Reputation score for the queried URL (refer to notes section for details on score classification) |
| $BCTIThreatHistory | The number of times that this site has had a security event in the past 12 months It is at least 1 for current security-compromised sites. |
| $BCTIAPIStatus | Returns the API status code of the request made |


##### Retrieve WHOIS information on the URL

This endpoint returns abbreviated WHOIS information on the URL
- input : A URL for which you want to retrieve information.

```
_fetch $Url from threatsample limit 1
>>_lookup webroot get_url_whoisinfo $Url
```

##### Sample walk-through video link for URL WHOIS 
[URL WHOIS](https://drive.google.com/file/d/11EvQPXkZAR1Xe39C0UWWwpvMSPHZZiJX/view?usp=sharing)

The Lookup call returns output in the following structure for available data  

 | Fields        | Description  |
|:------------- |:-------------|
| $BCTIAuditUpdateDate | Date of audit update date |
| $BCTIContactEmail | Email address of contact |
| $BCTICreatedDate | Created date of the domain associated with the URL  |
| $BCTIDomainName | Domain Name |
| $BCTIExpiresDate | Expiry date of the domain associated with the URL |
| $BCTINameServers | Associated name servers details   |
| $BCTIRegistrantCity  | City of the registrant |
| $BCTIRegistrantCountry | Country of the registrant |
| $BCTIRegistrantEmail  | Email contact of registrant  |
| $BCTIRegistrantName  |  Name of the registrant  |
| $BCTIRegistrantOrganization  | Organization of the registrant  |
| $BCTIRegistrantPostalCode  | Postal Code of the registrant  |
| $BCTIRegistrantState  | State of the registrant   |
| $BCTIRegistrantStreet  | Street of the registrant  |
| $BCTIRegistrantTelephone  | Telephone of the registrant  |
| $BCTIRegistrarName  | Name of the Registrar  |
| $BCTIStandardRegCreatedDate  | Standard registry created date |
| $BCTIStandardRegExpiresDate | Standard registry expiry date  |
| $BCTIStandardRegUpdatedDate | Standard registry updated date  |
| $BCTIAPIStatus | Returns the API status code of the request made |

#####  Retrieve full WHOIS info on the URL.
  
This endpoint returns full WHOIS information on the URL
- input : a md5/sha1/sha256 hash will retrieve the most recent report on a given sample
```
_fetch $Url from threatsample limit 1
>>_lookup webroot get_url_whoisinfofull $Url
```
##### Sample walk-through video link for full URL WHOIS 
[URL WHOIS FULL](https://drive.google.com/file/d/1Db5aht1vC3KyjnNr4F38HI1dCgFg33t_/view?usp=sharing)


The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $BCTIAuditUpdateDate | Date of audit update date |
| $BCTIContactEmail | Email address of contact |
| $BCTICreatedDate | Created date of the domain associated with the URL  |
| $BCTIDomainName | Domain Name |
| $BCTIExpiresDate | Expiry date of the domain associated with the URL |
| $BCTINameServers | Associated name servers details   |
| $BCTIRegistrantCity  | City of the registrant |
| $BCTIRegistrantCountry | Country of the registrant |
| $BCTIRegistrantEmail  | Email contact of registrant  |
| $BCTIRegistrantName  |  Name of the registrant  |
| $BCTIRegistrantOrganization  | Organization of the registrant  |
| $BCTIRegistrantPostalCode  | Postal Code of the registrant  |
| $BCTIRegistrantState  | State of the registrant   |
| $BCTIRegistrantStreet  | Street of the registrant  |
| $BCTIRegistrantTelephone  | Telephone of the registrant  |
| $BCTIRegistrarName  | Name of the Registrar  |
| $BCTIStandardRegCreatedDate  | Standard registry created date |
| $BCTIStandardRegExpiresDate | Standard registry expiry date  |
| $BCTIStandardRegUpdatedDate | Standard registry updated date  |
| $BCTIAPIStatus | Returns the API status code of the request made |


### Using the WEBROOT BRIGHTCLOUD THREAT INTELLIGENCE API and DNIF  
The BRIGHTCLOUD THREAT INTELLIGENCE API is found on github at 

  https://github.com/dnif/lookup-webroot

#### Getting started with WEBROOT BRIGHTCLOUD THREAT INTELLIGENCE API and DNIF

1. #####    Login to your Data Store, Correlator, and A10 containers.  
   [ACCESS DNIF CONTAINER VIA SSH](https://dnif.it/docs/guides/tutorials/access-dnif-container-via-ssh.html)
2. #####    Move to the ‘/dnif/<Deployment-key/lookup_plugins’ folder path.
```
$cd /dnif/CnxxxxxxxxxxxxV8/lookup_plugins/
```
3. #####   Clone using the following command  
```  
git clone https://github.com/dnif/lookup-webroot.git webroot
```
4. #####   Move to the ‘/dnif/<Deployment-key/lookup_plugins/webroot/’ folder path and open dnifconfig.yml configuration file     
    
   Replace the <tags> with your WEBROOT BRIGHTCLOUD THREAT INTELLIGENCE oemid,deviceid,uid
```
lookup_plugin:
  BRIGHTCLOUD_OEMID: <Add_your_oemid_here>
  BRIGHTCLOUD_DEVICEID: <Add_your_deviceid_here>
  BRIGHTCLOUD_UID: <Add_your_uid_here>
  
```
