FROM python:2.7

ADD ise_grouping_formatting.py /
ADD pf_grouping_formatting.py /
ADD pa_grouping_formatting.py /
ADD splunk-API.py /
ADD ise.csv /
ADD pf.csv /
ADD pa.csv /
ADD scores.csv /

RUN pip install flask
RUN pip install ipaddress
RUN pip install requests
RUN pip install numpy
RUN pip install pandas 
RUN pip install datetime


CMD [ "python", "./splunk-API.py" ]