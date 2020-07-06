# masters-research

This is the API that has been used to collect the logs from Splunk, process them, and generate the score for each log type. 
Here is how it works: 

- the first step is in the file splunkAPI.py. This is where all the endpoints are defined. Those endpoints will be receiving the logs. Each endpoint takes care of a different log type.

- Once the endopoint has received a log, it saves it to a csv file. This file is then going to be processed by a script (either ise_grouping_formatting.py, pf_grouping_formatting.py or pa_grouping_formatting.py, depending on the log type). The processing consists in formatting the log so it can be ingested by a machine learning ML, send the formatted logs to the ML model and receive the resulting score.

- Finally, once the scripts are done running, they save the resulting score into the file scores.csv.

Notes: 
- if you wish to test this code, you need to make this API acccessible, so the easiest way would be to use ngrok. By default, the API runs on localhost, port 5000. To launch the API, you need to type in the following command:
```console
foo@bar:~$ python splunk-API.py
```
- now you need to make this port accessible to any POST request, so you need to download the ngrok executable (https://ngrok.com/), and type in the following command to execute the file: 
```console
foo@bar:~$ ./ngrok http 5000
```

- this will automatically generate a link which will redirect to localhost port 5000 where your api is running.
let's say the link is "http://myapi.ngrok.io", if you wish to make a POST request, you need to specify the path to the relevant endpoint. There are 3 endpoint: "ISE","PF" and "PA". So for example, the link to send logs to the ISE endpoint would be: "http://myapi.ngrok.io/ISE"

Limitation: 
- The only issue with this setup is that it only works if the relevant Splunk alerts are setup. In fact, once your link is generated, you need to specify this link in the splunk alerts so they can send the logs to the right address. but since ngrok links expire after 8 hours, you constantly need to edit the Splunk alerts. This is why I decided to deploy this code on a docker management platform which is unfortunately not open to the public (company managed).  
