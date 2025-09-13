FROM python
MAINTAINER Olexii Chernov <chernovoleksiy@gmail.com>
RUN python3 -m venv /home/ReadLogsSuricata/virtualenv
RUN pip3 install pandas matplotlib flask maxminddb requests geoip2 python-whois
COPY ./static /home/ReadLogsSuricata/static
COPY ./templates /home/ReadLogsSuricata/templates
COPY app.py /home/ReadLogsSuricata
COPY GeoLite2-City.mmdb /home/ReadLogsSuricata
EXPOSE 5030
CMD FLASK_APP=/home/ReadLogsSuricata/app.py flask run -h 0.0.0.0 -p 5030
