#! /usr/bin/python
from time import sleep
import requests
from lxml import etree
import matplotlib.pyplot as plot

uptimes = []
covers = []

for i in range(10):
    f = requests.get(url="http://127.0.0.1:56741", verify=False)
    html = etree.HTML(f.content)
    uptime = html.xpath("/html/body/table[1]/tr[3]/td[2]/text()")[0].strip()
    cover = html.xpath("/html/body/table[1]/tr[8]/td[2]/a/text()")[0].strip()
    uptimes.append(uptime)
    covers.append(cover)
    sleep(1)
plot.plot(uptimes, covers)
plot.xlabel("uptime / s")
plot.ylabel("cover")
plot.title("demo")
plot.show()
