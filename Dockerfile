FROM thanhlong9x/centos7.8:v1
RUN yum install -y python3-pip 
RUN pip3 install -y kubernetes==12.0.1
RUN pip3 install -y ipaddress
RUN mkdir /home/csde
COPY csde.py /home/csde
USER 1000:1000
WORKDIR /home/csde
ENTRYPOINT ["/usr/bin/python3","csde.py"]