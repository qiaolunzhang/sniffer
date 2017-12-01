# sniffer

## requirements
```
# gtk3 for C
sudo apt-get install libgtk-3-dev
# to capture packet
sudo apt-get install libpcap-dev
# debug for qtcreator
sudo apt-get install gdb
# for lGL
sudo apt-get install libgl-dev
```
*for libpcap work in qt*
just add the following line to your .pro file 
```
LIBS += -L/usr/local/lib/ -lpcap

```


## structure of the program
- sniffer.cpp
命令行下的sniffer程序
- init.h
定义的变量以及程序刚开始运行时的几个函数
