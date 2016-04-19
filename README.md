# IAP
This contains course work for Internet Architecture and Protocol Lab.

First we need to copy the newly created pwospf packet to right location.
Run the following command in the terminal:
```
cp pox_pwosf_packet/* ~/pox/pox/lib/packet/
```

We also need to place the controller `router.py` into the right location:
```
cp router.py ~/pox/pox/misc/
```

Running the controller `router.py`:
```
pox/pox.py log.level --DEBUG misc.router
```

Set up topology:
```
sudo python topology.py
```