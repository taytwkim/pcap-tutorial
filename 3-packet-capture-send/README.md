# Capturing and Sending Packets

1. Install PcapPlusPlus.

2. Build using CMake from project root.

```shell
cmake -S 3-packet-capture-send -B build/3-packet-capture-send
cmake --build build/3-packet-capture-send
```

3. Change to the `3-packet-capture-send/` directory and run the executable:

```shell
cd 3-packet-capture-send
./Tutorial-LiveTraffic
```