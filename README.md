# sniffer

## requirements
```
# for qtcreater
sudo apt-get install libgtk-3-dev
sudo apt-get install libpcap-dev
```
*for libpcap work in qt*
just add the following line to your .pro file 
```
LIBS += -L/usr/local/lib/ -lpcap

```


## structure of the program
- sniffer.c 
a program find in the internet

- find-device.c
a program to print out the device that is using now
