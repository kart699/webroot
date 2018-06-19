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
| 5  | Unranked site |

##### Retrieve URL information  
This endpoint returns content classification and reputation information on the queried URL.
- input : An URL for which you want to retrieve information.        
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
- input : An URL for which you want to retrieve information.

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
- input : An URL for which you want to retrieve information.

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
- input : A md5/sha1/sha256 hash will retrieve the most recent report on a given sample
```
_fetch $Url from threatsample limit 1
>>_lookup webroot get_url_whoisinfofull $Url
```
##### Sample walk-through video link for full URL WHOIS 
[URL WHOIS FULL](https://drive.google.com/file/d/1Db5aht1vC3KyjnNr4F38HI1dCgFg33t_/view?usp=sharing)


The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $BCTIAdministrativeContactCity | Administration contact city |
| $BCTIAdministrativeContactCountry | Administration contact country |
| $BCTIAdministrativeContactEmail | Administration contact email |
| $BCTIAdministrativeContactFax | Administration contact fax |
| $BCTIAdministrativeContactFaxext | Administration contact fax extention |
| $BCTIAdministrativeContactName |  Administration contact name|
| $BCTIAdministrativeContactOrganization | Administration contact organization |
| $BCTIAdministrativeContactPostalCode | Administration contact postal code |
| $BCTIAdministrativeContactState | Administration contact state |
| $BCTIAdministrativeContactStreet1 | Administration contact street 1 |
| $BCTIAdministrativeContactStreet2 |  Administration contact street 2 |
| $BCTIAdministrativeContactStreet3 |  Administration contact street 3 |
| $BCTIAdministrativeContactStreet4 |  Administration contact street 4 |
| $BCTIAdministrativeContactTelephone |  Administration contact telephone |
| $BCTIAdministrativeContactTelephoneExt | Administration contact telephone extention |
| $BCTIAuditUpdateDate | Date of audit update |
| $BCTIContactEmail | Email address of contact |
| $BCTICreatedDate | Created date of the domain associated with the URL  |
| $BCTIUpdatedDate | Update date of the domain associated with the URL |
| $BCTIExpiresDate | Expiry date of the domain associated with the URL |
| $BCTIDomainName | Domain Name |
| $BCTINameServers | Associated name servers details   |
| $BCTIRegistrantCity  | City of the registrant |
| $BCTIRegistrantCountry | Country of the registrant |
| $BCTIRegistrantEmail  | Email contact of registrant  |
| $BCTIRegistrantFax | Fax details of registrant |
| $BCTIRegistrantFaxext | Fax extention of registrant |
| $BCTIRegistrantName  |  Name of the registrant  |
| $BCTIRegistrantOrganization  | Organization of the registrant  |
| $BCTIRegistrantPostalCode  | Postal Code of the registrant  |
| $BCTIRegistrantState  | State of the registrant   |
| $BCTIRegistrantStreet1  | Street address of the registrant  |
| $BCTIRegistrantStreet2  | Street address of the registrant  |
| $BCTIRegistrantStreet3  | Street address of the registrant  |
| $BCTIRegistrantStreet4  | Street address of the registrant  |
| $BCTIRegistrantTelephone  | Telephone of the registrant  |
| $BCTIRegistrantTelephoneext  | Telephone extention of the registrant   |
| $BCTIRegistrantPostalCode | Postal code of registrant |
| $BCTIWhoIsServer | WHOIS Server name |
| $BCTIRegistrarName  | Name of the Registrar  |
| $BCTIStandardRegCreatedDate  | Standard registry created date |
| $BCTIStandardRegExpiresDate | Standard registry expiry date  |
| $BCTIStandardRegUpdatedDate | Standard registry updated date  |
| $BCTIstatus | Status of domain associated with domain |
| $BCTIAPIStatus | Returns the API status code of the request made |

##### Retrieve the phishing score on the object (URL or IP). 
This endpoint is a synchronous call soserver waits for all URIs to be processed before response to the request.
- input : An URL or IP for which you want to retrieve information.        
```
_fetch $SrcIP from threatsample limit 1
>>_lookup webroot get_phishingscore $SrcIP
```
###### Sample Output 
![get_phishingscore](https://user-images.githubusercontent.com/37173181/41521924-b0e67cb6-72f1-11e8-8da4-cf85a5c188da.jpg)
The Lookup call returns output in the following structure for available data

  | Fields        | Description  |
|:------------- |:-------------|
| $BCTIPhishScore   | Threat level returned from BCTI ranges from 1 to 100. The higher the score, the higher probability that the url is a phishing site. |
| $BCTIPhishTarget  | Target of the phishing |
| $BCTIAPIStatus| Returns the API status code of the request made |


##### Submit phishquery on the object (URL or IP). 
This endpoint is used for sending URIs (URL or IP) where you call back later to get result.
- input : An URL or IP for which you want to retrieve information.        
```
_fetch $SrcIP from threatsample limit 1
>>_lookup webroot submit_phishquery $SrcIP
>>_store in_disk wbticket stack_replace
```
###### Sample Output 

![get_submitphishquerywithstore](https://user-images.githubusercontent.com/37173181/41522871-8d827e6a-72f5-11e8-8610-1fa24f65d851.jpg)

The Lookup call returns output in the following structure for available data

  | Fields        | Description  |
|:------------- |:-------------|
| $BCTIPhishRequestTicket  | Returns a phishresponse ticket which can be used to query later  |
| $BCTIAPIStatus| Returns the API status code of the request made |

##### Note 
The returned $BCTIPhishRequestTicket can be stored in the DNIF console using the store directive .  
Which can later be used to retrive response with the  get_phishqueryresponse endpoint.

            
##### Retrieve the phish query response for the ticket. 
This endpoint uses the phishrequestticket to request result.
- input : String of phish request ticket.        
```
_retrieve wbticket 
>>_lookup webroot get_phishqueryresponse $BCTIPhishRequestTicket
```
###### Sample Output 

![get_phishqueryresponse](https://user-images.githubusercontent.com/37173181/41523643-6421825c-72f8-11e8-9c9b-b9d122ddca45.jpg)

The Lookup call returns output in the following structure for available data

  | Fields        | Description  |
|:------------- |:-------------|
| $BCTIPhishScore   | Threat level returned from BCTI ranges from 1 to 100. The higher the score, the higher probability that the url is a phishing site. |
| $BCTIPhishTarget  | Target of the phishing |
| $BCTIAPIStatus| Returns the API status code of the request made |

##### Note 
using the stored ticket from the submit phishquery endpoint we retrieve the information from this endpoint

##### Retrieve IP information  
This endpoint returns content classification and reputation information on the queried IP address.
- input : An IP address for which you want to retrieve information.        
```
_fetch $Url from threatsample limit 1
>>_lookup webroot get_url_info $Url
```
###### Sample Output 
![get_ip_info](https://user-images.githubusercontent.com/37173181/41530733-c4780f48-730e-11e8-90aa-31c1990e039a.jpg)

The Lookup call returns output in the following structure for available data

  | Fields        | Description  |
|:------------- |:-------------|
| $BCTIIPInt    | Integer representation of the requested IP Address. |
| $BCTIIPStatus | Binary value of the Threat IP status.Possible values are (1 and 2), 1 means in Threat IP list ,0 means not in Threat IP list |
| $BCTICurrentReleaseDate | Represents the exit date that the Threat IP is removed from the Threat IP list. This field is empty if the IP Address is no longer in the Threat IP list |
| $BCTIDomain | If IP Address has a corresponding unique domain name in Webroot Master DB, the domain name is shown here empty if not in Master DB) |
| $BCTIDomainAge | The age of the unique domain associated with the IP Address in Webroot Master DB since the discovery of the domain by Webroot (empty if not in Master DB) |
| $BCTIFirstReleaseDate | Represents the date associated with the first time that an IP Address is released from the   Threat IP list. |
| $BCTILastReleaseDate  | Represents the date associated with the last time that an IP Address is released from the    Threat IP list.  |
| $BCTIThreatCount  | The number of times the IP address has appeared on Threat IP list.  |
| $BCTIThreatMask  | Information on specific threat(s) that associated with requested IP. Bit number corresponds with the Threat Mask category.  |
| $BCTIReputation  | Reputation score from 1-100 of this IP.  |
| $BCTIAPIStatus| Returns the API status code of the request made |


##### Retrieve IP geo information  
This endpoint returns geo information on the queried IP address.
- input : An IP address for which you want to retrieve information.        
```
_fetch $SrcIP from threatsample limit 1
>>_lookup webroot get_ip_geoinfo $SrcIP
```
###### Sample walk-through video link for IP geo information

[Get IP GEO INFO](https://drive.google.com/file/d/1KpBZxloQ3OT29lzb3H3TwJpuhATDFX8y/view?usp=sharing)
The Lookup call returns output in the following structure for available data

  | Fields        | Description  |
|:------------- |:-------------|
| $BCTIASN    | Autonomous system number where this ip belongs to  |
| $BCTICarrier | Carrier where this ip belongs to |
| $BCTICity | City name from geo file |
| $BCTICountry | Country name from geo file |
| $BCTIRegion  | Region name from geo file  |
| $BCTIState  | State name from geo file  |
| $BCTILatitude | Latitude of this ip |
| $BCTILongitude | Longitude of this ip |
| $BCTIOrganization  | Organization where this ip belongs to  |
| $BCTISecondLevelDomain  | Second-level domain of this ip  |
| $BCTITopLevelDomain | Top-level domain of this ip |
| $BCTIAPIStatus| Returns the API status code of the request made |

##### Retrieve IP threat history   
This endpoint returns threat history of the requested IP.
- input : An IP address for which you want to retrieve information.        
```
_fetch $SrcIP from threatsample limit 1
>>_lookup webroot get_ip_threathistory $SrcIP
```
###### Sample walk-through video link for IP threat history
[GET IP THREATHISTORY](https://drive.google.com/file/d/1DoSttzPMvL2I7rpMSRWc3ZLPNz1Ll9tR/view?usp=sharing)

The Lookup call returns output in the following structure for available data

  | Fields        | Description  |
|:------------- |:-------------|
| $BCTIThreatTypes    | Autonomous system number where this ip belongs to  |
| $BCTIThreatCount | Carrier where this ip belongs to |
| $BCTIAPIStatus| Returns the API status code of the request made |

The report also includes variable fields depending on the positive detections. For example, an ip identified as threat type botnets  would have the following fields

  | Fields        | Description  |
|:------------- |:-------------|
| $BCTIThreatTypeBotnets | a list of timestamp when the IP was seen as a botnet  |


##### Retrieve IP reputation history   
This endpoint returns This call returns the historic reputation score for the requested IPs. Prior to September 27, 2015 the reputation scoring is rounded. A new scoring history is recorded for an IP only if the change in reputation score exceeds a preset threshold or if there is a change in threat status (threat/non-threat)

- input : An IP address for which you want to retrieve information.        
```
_fetch $SrcIP from threatsample limit 1
>>_lookup webroot get_ip_rephistory $SrcIP
```
###### Sample walk-through video link for IP reputation history
[GET IP REPUTATION HISTORY ](https://drive.google.com/file/d/1sV8Vhqe0AZhBkn26W7QU1nYeSe_aaovy/view?usp=sharing)

The Lookup call returns output in the following structure for available data

  | Fields        | Description  |
|:------------- |:-------------|
| $BCTIAverageReputation   | Decimal number representing the average reputation of the IP  |
| $BCTIHistoryCount | Number representing the number of time the IP reputation is recorded. |
| $BCTIMaxReputation | Number representing the highest recorded reputation of the IP |
| $BCTIMinReputation | Number representing the lowest recorded reputation of the IP |
| $BCTIReputationHighRisk | List of time stamp when IP had a high risk reputation  |
| $BCTIReputationSuspicious | List of time stamp when IP had a suspicious reputation  |
| $BCTIReputationTrustworthy | List of time stamp when IP had a Trustworthy reputation |
| $BCTIAPIStatus| Returns the API status code of the request made |


##### Retrieve file information 
This endpoint returns file information given its binary MD5 .
- input : String of MD5 of file for which you want to retrieve information.        
```
_fetch $Filehash from threatsample where $Filehash=ec8c89aa5e521572c74e2dd02a4daf78 limit 1
>>_lookup webroot get_file_info $Filehash
```
###### Sample walk-through video link for file information
[GET FILE INFO](https://drive.google.com/file/d/1i50yeKcTShvKZC7Gu8K7cMwzpv6zzgTl/view?usp=sharing)
The Lookup call returns output in the following structure for available data

  | Fields        | Description  |
|:------------- |:-------------|
| $BCTIDeterminationDate   | Determination time of this file . |
| $BCTIDeterminationType | Determination type. Possible values : B and G. |
| $BCTIFileSize | File size in byte . |
| $BCTIFirstSeen | First time the md5 has been detected . |
| $BCTIMalwareGroup | Malware group of this file . |
| $BCTIMd5 | The MD5 of the file . |
| $BCTIPropagationCount | Scaled approximation of the propagation of the file . |
| $BCTIAPIStatus| Returns the API status code of the request made . |


##### Retrieve IP reputation history   
This endpoint returns the historic reputation score for the requested IPs. Prior to September 27, 2015 the reputation scoring is rounded. A new scoring history is recorded for an IP only if the change in reputation score exceeds a preset threshold or if there is a change in threat status (threat/non-threat)

- input : An IP address for which you want to retrieve information.        
```
_fetch $SrcIP from threatsample limit 1
>>_lookup webroot get_ip_rephistory $SrcIP
```
###### Sample walk-through video link for IP reputation history
[GET IP REPUTATION HISTORY ](https://drive.google.com/file/d/1sV8Vhqe0AZhBkn26W7QU1nYeSe_aaovy/view?usp=sharing)

The Lookup call returns output in the following structure for available data

  | Fields        | Description  |
|:------------- |:-------------|
| $BCTIAverageReputation   | Decimal number representing the average reputation of the IP  |
| $BCTIHistoryCount | Number representing the number of time the IP reputation is recorded. |
| $BCTIMaxReputation | Number representing the highest recorded reputation of the IP |
| $BCTIMinReputation | Number representing the lowest recorded reputation of the IP |
| $BCTIReputationHighRisk | List of time stamp when IP had a high risk reputation  |
| $BCTIReputationSuspicious | List of time stamp when IP had a suspicious reputation  |
| $BCTIReputationTrustworthy | List of time stamp when IP had a Trustworthy reputation |
| $BCTIAPIStatus| Returns the API status code of the request made |


##### Retrieve contextual domain stats  
This endpoint returns the extended contextual information for the domain. The response contains the counts of related entities grouped on different threat levels (0-4). For example: the count of virtually hosted domains, sub domains, etc.

- input : A domain for which you want to retrieve information.        
```
_fetch $Domain from threatsample limit 1
>>_lookup webroot get_contextual_domainstats $Domain
```
###### Sample walk-through video link for contextual domain stats


### Note 
Reputation score classification

| Reputation range       | Threat level |
|:------------- |:-------------|
|  1 - 20 | Level 0 |
| 21 – 40 | Level 1 |
| 41 – 60 | Level 2 |
| 61 – 80 | Level 3 |
| 81 – 100 | Level 4 |

The Lookup call returns output in the following structure for available data

  | Fields        | Description  |
|:------------- |:-------------|
| $BCTICommonRegistrantThreatLevel0 | Representing the count of domains that share the same registrant information with this domain at threat level 0 |
| $BCTICommonRegistrantThreatLevel1 | Representing the count of domains that share the same registrant information with this domain at threat level 1 |
| $BCTICommonRegistrantThreatLevel2 | Representing the count of domains that share the same registrant information with this domain at threat level 2  |
| $BCTICommonRegistrantThreatLevel3 | Representing the count of domains that share the same registrant information with this domain at threat level 3  |
| $BCTICommonRegistrantThreatLevel4 | Representing the count of domains that share the same registrant information with this domain at threat level 4  |
| $BCTIVirtuallyHostedThreatLevel0 | Representing the count of all virtually hosted domains at threat level 0 |
| $BCTIVirtuallyHostedThreatLevel1 | Representing the count of all virtually hosted domains at threat level 1 |
| $BCTIVirtuallyHostedThreatLevel2| Representing the count of all virtually hosted domains at threat level 2 |
| $BCTIVirtuallyHostedThreatLevel3| Representing the count of all virtually hosted domains at threat level 3 |
| $BCTIVirtuallyHostedThreatLevel4| Representing the count of all virtually hosted domains at threat level 4 |
| $BCTIHostingIPsThreatLevel0 | Representing the count of IPs which host this domain at threat level 0 |
| $BCTIHostingIPsThreatLevel1 | Representing the count of IPs which host this domain at threat level 1 |
| $BCTIHostingIPsThreatLevel2 | Representing the count of IPs which host this domain at threat level 2 |
| $BCTIHostingIPsThreatLevel3 | Representing the count of IPs which host this domain at threat level 3 |
| $BCTIHostingIPsThreatLevel4 | Representing the count of IPs which host this domain at threat level 4 |
| $BCTIHostedAppsThreatLevel0 | Representing the count of all hosted mobile apps at threat level 0 |
| $BCTIHostedAppsThreatLevel1 | Representing the count of all hosted mobile apps at threat level 1 |
| $BCTIHostedAppsThreatLevel2 | Representing the count of all hosted mobile apps at threat level 2 |
| $BCTIHostedAppsThreatLevel3 | Representing the count of all hosted mobile apps at threat level 3 |
| $BCTIHostedAppsThreatLevel4 | Representing the count of all hosted mobile apps at threat level 4 |
| $BCTIHostedFilesThreatLevel0  | Representing the count of all hosted files at threat level 0 |
| $BCTIHostedFilesThreatLevel1  | Representing the count of all hosted files at threat level 1 |
| $BCTIHostedFilesThreatLevel2  | Representing the count of all hosted files at threat level 2 |
| $BCTIHostedFilesThreatLevel3  | Representing the count of all hosted files at threat level 3 |
| $BCTIHostedFilesThreatLevel4  | Representing the count of all hosted files at threat level 4 |
| $BCTISubDomainsThreatLevel0  | Representing the count of all sub domains from this domain at threat level 0  |
| $BCTISubDomainsThreatLevel1  | Representing the count of all sub domains from this domain at threat level 1  |  
| $BCTISubDomainsThreatLevel2  | Representing the count of all sub domains from this domain at threat level 2  |
| $BCTISubDomainsThreatLevel3  | Representing the count of all sub domains from this domain at threat level 3  |
| $BCTISubDomainsThreatLevel4  | Representing the count of all sub domains from this domain at threat level 4  |
| $BCTIAPIStatus| Returns the API status code of the request made |



##### Retrieve contextual IP stats  
This endpoint returns extended contextual information for the IP. The response contains the counts of related entities grouped on different threat levels (0-4)

- input : An IP address for which you want to retrieve information.        
```
_fetch $SrcIP from threatsample limit 1
>>_lookup webroot get_contextual_ipstats $SrcIP
```
###### Sample walk-through video link for contextual IP stats
[GET CONTEXTUAL IP STATS](https://drive.google.com/file/d/1F6fBOk_ScCDu1Rh7_fdGnOElxRobGoqf/view?usp=sharing)


### Note 
Reputation score classification

| Reputation range       | Threat level |
|:------------- |:-------------|
|  1 - 20 | Level 0 |
| 21 – 40 | Level 1 |
| 41 – 60 | Level 2 |
| 61 – 80 | Level 3 |
| 81 – 100 | Level 4 |

The Lookup call returns output in the following structure for available data

  | Fields        | Description  |
|:------------- |:-------------|
| $BCTIASNThreatLevel0 | Representing the count of all IPs that share the same asn of this IP at threat level 0 |
| $BCTIASNThreatLevel1 | Representing the count of all IPs that share the same asn of this IP at threat level 1 |
| $BCTIASNThreatLevel2| Representing the count of all IPs that share the same asn of this IP at threat level 2 |
| $BCTIASNThreatLevel3| Representing the count of all IPs that share the same asn of this IP at threat level 3 |
| $BCTIASNThreatLevel4| Representing the count of all IPs that share the same asn of this IP at threat level 4 |
| $BCTIHostedURLsThreatLevel0 | Representing the count of all virtually hosted domains at threat level 0 |
| $BCTIHostedURLsThreatLevel1 | Representing the count of all virtually hosted domains at threat level 1 |
| $BCTIHostedURLsThreatLevel2 | Representing the count of all virtually hosted domains at threat level 2 |
| $BCTIHostedURLsThreatLevel3 | Representing the count of all virtually hosted domains at threat level 3 |
| $BCTIHostedURLsThreatLevel4 | Representing the count of all virtually hosted domains at threat level 4 |
| $BCTIHostedAppsThreatLevel0 | Representing the count of all hosted mobile apps at threat level 0 |
| $BCTIHostedAppsThreatLevel1 | Representing the count of all hosted mobile apps at threat level 1 |
| $BCTIHostedAppsThreatLevel2 | Representing the count of all hosted mobile apps at threat level 2 |
| $BCTIHostedAppsThreatLevel3 | Representing the count of all hosted mobile apps at threat level 3 |
| $BCTIHostedAppsThreatLevel4 | Representing the count of all hosted mobile apps at threat level 4 |
| $BCTIHostedFilesThreatLevel0  | Representing the count of all hosted files at threat level 0 |
| $BCTIHostedFilesThreatLevel1  | Representing the count of all hosted files at threat level 1 |
| $BCTIHostedFilesThreatLevel2  | Representing the count of all hosted files at threat level 2 |
| $BCTIHostedFilesThreatLevel3  | Representing the count of all hosted files at threat level 3 |
| $BCTIHostedFilesThreatLevel4  | Representing the count of all hosted files at threat level 4 |
| $BCTIAPIStatus| Returns the API status code of the request made |


##### Retrieve contextual File stats  
This endpoint returns the extended contextual information for the File represented by its MD5 string. The response contains the counts of related entities grouped on different threat levels (0-4). For example: the count of outbound ips, hosting ips, etc.

- input : A MD5 string for which you want to retrieve information.        
```
_fetch $Filehash from threatsample where $Filehash=195a7ef654ca94d9aff5142d139f9486 limit 1
>>_lookup webroot get_contextual_filestats $Filehash
```

###### Sample walk-through video link for contextual IP stats
[GET CONTEXTUAL FILE STATS](https://drive.google.com/file/d/1UTii1OjsCWiEtsZp6c7rcGvIpQlTiW6n/view?usp=sharing)


### Note 
Reputation score classification

| Reputation range       | Threat level |
|:------------- |:-------------|
|  1 - 20 | Level 0 |
| 21 – 40 | Level 1 |
| 41 – 60 | Level 2 |
| 61 – 80 | Level 3 |
| 81 – 100 | Level 4 |

The Lookup call returns output in the following structure for available data

  | Fields        | Description  |
|:------------- |:-------------|
| $BCTIHostingIPsThreatLevel0 | Representing the count of all IPs that host this file at threat level 0 |
| $BCTIHostingIPsThreatLevel1 | Representing the count of all IPs that host this file at threat level 1 |
| $BCTIHostingIPsThreatLevel2| Representing the count of all IPs that host this file at threat level 2 |
| $BCTIHostingIPsThreatLevel3| Representing the count of all IPs that host this file at threat level 3 |
| $BCTIHostingIPsThreatLevel4| Representing the count of all IPs that host this file at threat level 4 |
| $BCTIHostingURLsThreatLevel0 | Representing the count of all URLs that host this file at threat level 0 |
| $BCTIHostingURLsThreatLevel1 | Representing the count of all URLs that host this file at threat level 1 |
| $BCTIHostingURLsThreatLevel2 | Representing the count of all URLs that host this file at threat level 2 |
| $BCTIHostingURLsThreatLevel3 | Representing the count of all URLs that host this file at threat level 3 |
| $BCTIHostingURLsThreatLevel4 | Representing the count of all URLs that host this file at threat level 4 |
| $BCTIOutboundIPsThreatLevel0 | Representing the count of all IPs that this file connects to at threat level 0 |
| $BCTIOutboundIPsThreatLevel1 | Representing the count of all IPs that this file connects to at threat level 1 |
| $BCTIOutboundIPsThreatLevel2 | Representing the count of all IPs that this file connects to at threat level 2 |
| $BCTIOutboundIPsThreatLevel3 | Representing the count of all IPs that this file connects to at threat level 3 |
| $BCTIOutboundIPsThreatLevel4 | Representing the count of all IPs that this file connects to at threat level 4 |
| $BCTIOutboundURLsThreatLevel0  | Representing the count of all URLs that this file connects to at threat level 0  |
| $BCTIOutboundURLsThreatLevel1  | Representing the count of all URLs that this file connects to at threat level 1 |
| $BCTIOutboundURLsThreatLevel2  | Representing the count of all URLs that this file connects to at threat level 2 |
| $BCTIOutboundURLsThreatLevel3  | Representing the count of all URLs that this file connects to at threat level 3 |
| $$BCTIOutboundURLsThreatLevel4  | Representing the count of all URLs that this file connects to at threat level 4 |
| $BCTIAPIStatus| Returns the API status code of the request made |

##### Retrieve IP threatinsight  
This endpoint returns a list of incidents which caused an IP to be flagged as malicious. The response contains the earliest time the incidents were observed, the length of the time the incidents were ongoing, whether the series of incidents was severe enough for the IP to be determined as threat, the specific type of threat(s) detected, and any additional, type-dependent details available for the IP

- input : An IP address for which you want to retrieve information.        
```
_fetch $SrcIP from threatsample limit 1
>>_lookup webroot get_ipthreatinsight $SrcIP
```

###### Sample Output
![GET IP THREATINSIGHT](https://user-images.githubusercontent.com/37173181/41598480-e534b7c4-73ed-11e8-9066-2e03f8951414.jpg)

The Lookup call returns output in the following structure for available data

  | Fields        | Description  |
|:------------- |:-------------|
| $BCTIThreatType | Threat found on the queried IP |
| $BCTIConvictedTime | List of timestamp when file was observed as convicted  |
| $BCTIHostType  | IP address Hosting example ZuesBot Cnc   |
| $BCTIHostedURLs  | List of hosting url  |
| $BCTIIPint  | Integer representation of the requested IP Address.  |
| $BCTIAPIStatus| Returns the API status code of the request made |


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
