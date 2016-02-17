# IAP
This contains course work for Internet Architecture and Protocol Lab.

Running the controller
Paste the controller.py file in the pox/pox/misc folder

`pox/pox.py log.level --DEBUG misc.controller`

Running mininet

`sudo mn --custom topo.py --topo mytopo --controller remote`

Delete earlier configuration

`sudo mn -c`
