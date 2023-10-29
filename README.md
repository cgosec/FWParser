# FWParser
Python command line tool for parsing raw firewall logs to a simple CSV or JSON representation. (With automated check against Threatfox listed IPs)

All **text** files can be processed. Works with **gz** or **xz** compressed files too.

# Why?

Speeding up checking firewall data in Incident Response when no SIEM is available and the FW data format sucks (as most of the time)...

This parser guides you through the file format you want to process. It will ask you for delimiter, possitions and allows you to work with replaces (they are some times needed because firewall logs of some vendors do not have a fixed position for relevant keys).

After you defined the delimiter, positions of:
- Source IP
- Destination IP
- Source Port
- Destination Port
- Date
- Time

and created needed replaces, you can save you sprecifications for the format in a config file so you do not have to follow the whole process for new data.

# Parameters
**-d DIR, --dir DIR**     

Use this to parse a whole directory. Make sure only valid text, gz or xz files are in there. (either -d or -f is needed)
  
**-f FILE, --file FILE**  

Use this to parse from a single file (either this or -d is needed)
  
**-t DELIMITER, --delimiter DELIMITER**

Use this to specify the delimiter. If empty you will be asked. Or it can be specified in the config file
                        
**-o OUTPUT, --output OUTPUT**

the path were the output files will be stored, cwd if not specified

**-n NAME, --name NAME**

use this if you want to parse everything into a single file. (without file extention)

**-ip FILTER_IP, --filter-ip FILTER_IP**

- 'threatfox' for IPs listed in threatfox https://threatfox.abuse.ch/export/ (default 30days. set -days for custom value);
- 'public' for only entries having a public IP in source or destination;
- single ip: eg. '192.168.0.1';
- list of IPs: eg. '192.168.0.1,192.168.0.5';
- range of ports: eg. '192.168.0.1-192.168.0.5' you can specify multiple ranges seperated by a ','    
                         
**-days THREATFOX_DAYS, --threatfox-days THREATFOX_DAYS**

'define range back in time for threatfox https://threatfox.abuse.ch/export/ 
IPs set to 0 will take the whole list. 
if not specified the default is 30 days

**-p FILTER_PORT, --filter-port FILTER_PORT**

- single port: eg. '53'or a 
- list of ports: eg. '53,443' or a 
- range of ports: eg. '1-1024' you can specify multiple ranges seperated by a ','

**-c CONFIG, --config CONFIG**

path to a config .json file

**-b BATCH_SIZE, --batch-size BATCH_SIZE**
                        
By default 10000 lines will be processed. You should not go below 1000. The higher, the more RAM is used, but likely quicker   

**-x {csv,json}, --format {csv,json}**

specify csv or json as output format

**-z, --disable-validation**

Disable the IP-Validation. This is only recommented for processing e.g. DNS or Proxy logs where the destination or source is no IP

**-m, --connection-map**  

outputs a connection map as a json file having for each source a dict of each destination having a dict of each destination port having a list of timestamps

**-v, --verbose**

see more output on the console

**-u, --debug**

set logging level to debug and verbose

**-s SKIP_FILES, --skip-files SKIP_FILES**

number of files to skip in the list negative values will start from the end of the (directory) list and let this number of files away   

**--help** 

for list of arguments


# Usage

## Process file

    python .\fwParser.py -f test_data\test_data.foo
  
### Delimiter
You will get the first line prompted and asked to specify a delimiter

![image](https://github.com/cgosec/FWParser/assets/147876916/0f82e6bd-127d-4a65-b6a2-b5295aa9cfe4)

type , and press Enter

### Replaces in lines

you will be asked for strings to replace. In the test_data.foo there are examples, we will come to this a bit later since we do not know yet.

![image](https://github.com/cgosec/FWParser/assets/147876916/ff502fa8-1d3a-41eb-ab67-a43bd710260f)

we leave blank since we are not aware of this is needed.

You will get an other line displayed and already splitted by your spefified delimiter and applied replaces for visual confimation.

![image](https://github.com/cgosec/FWParser/assets/147876916/d6352518-d879-4bd0-b6eb-622ebefa28d9)

### Specifying possitions

you will get the position and an example string prompted

![image](https://github.com/cgosec/FWParser/assets/147876916/9c204713-66b1-4868-be90-012dae802c85)

you will be asked to specify the position for
- source_ip
  - 0
- dest_ip
  - 1
- source_port *the ports sometimes can be directly behind the IP-Adresses. If so you can specify the delimiter instead of a position*
  - 2
- dest_port *will not be asked if a delimiter is specified at the source_port prompt*
  - 3
- pos_date
  - 4
- pos_time *just leave blank if the time is in one line with the date*
  - 5  

### Validating

you will be asked if you want to validate the data. Since this will only go thrgouh the first batch of data, this is not recommented if you work with filters. Chance is high that the first batch does not show results because of the filter and throw an error.

### Saving the config

You will be asked to save the config. I recommend doing so, since it is less effort manipulating the config file than going through all the steps again if you encounter anny issues. (Replaces are a good example).

press **y** and confirm
enter a config name without file extention

![image](https://github.com/cgosec/FWParser/assets/147876916/f85d67bc-a24b-49f5-83ca-3b6abacc9ff0)

### Processing

Now the parser does his job

![image](https://github.com/cgosec/FWParser/assets/147876916/ca28b4e8-b32c-448a-b938-83d707e91c17)

### Checking Data

![image](https://github.com/cgosec/FWParser/assets/147876916/31d61d39-d25c-46ed-94a0-c6441b3b1496)

Looks good so far... lets check the logs if the parser encountered any errors.

### Checking Logs

open the log file with the matching timestamp of execution

![image](https://github.com/cgosec/FWParser/assets/147876916/1d0668f1-57f4-4b3c-ba3b-1713ba170d27)

The first line is just the header. Therefore its not an issue that it has not been processed.

The next two errors are not okay for us, since there is relevant data in there but anyhow (like some firewall vendors do) there is some stuff in the log lines that destroy the position :( lets fix that...

### Fixing errors with replaces

lets check the position of the second line:

![image](https://github.com/cgosec/FWParser/assets/147876916/b12292fd-0eb8-4218-8268-e213b314295e)

it seems like we should get rid of the part "omethin_destroying_the_format_for_replace, " and then our positiions would fit the schema again.

Lets check the third line

![image](https://github.com/cgosec/FWParser/assets/147876916/e61a7715-f7fd-4335-965b-7814db814d78)

here it seems like we have to replace "this is not good here too...," and "somethin__more_destroying_the_format_for_replace," to have our correct positions.

#### adding replaces to the config

currently our config looks like this:

![image](https://github.com/cgosec/FWParser/assets/147876916/c3596dbb-aaa4-4384-a131-3c31b7c24312)

lets add our replaces:

since we do not want to insert anything we just prelace with "". (In some cases it could be neccessary to insert some placeholders with more delimiters in between to fit the schema)

![image](https://github.com/cgosec/FWParser/assets/147876916/cf0119f3-a9d9-43b1-88aa-397e3da090fc)


### Testing with new config

  python .\fwParser.py  -f test_data\test_data.foo -c .\testFW_config.json

Check the log file for errors:

Sweet - only the header was threw an error!

![image](https://github.com/cgosec/FWParser/assets/147876916/1bbd72d5-00dc-4283-8485-b17ec9a89ed2)

Lets check the output file:

![image](https://github.com/cgosec/FWParser/assets/147876916/64c4b8f4-0e99-49d6-bdc5-185aa15c7cc0)

seems like our files have been processed correctly! :)

## Automatic Threatfox check

You can filter for known maliciouse connections by specifying the threatfox filter

    python .\fwParser.py -ip threatfox -days 3 -f .\test_data\test_data.foo --debug -c .\testFW_config.json

This automatically downloads the threatfox IP IOC file and adds all IPs within the timeframe in the IP Filters list.

You will see additional information form threatfox about the IP that has been found:

![image](https://github.com/cgosec/FWParser/assets/147876916/c7a6a974-cbd6-4d9c-8d45-6c70284459eb)



