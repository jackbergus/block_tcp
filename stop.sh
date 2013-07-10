#!/bin/sh
killall block_tcp
sudo iptables -D OUTPUT -p tcp -j NFQUEUE --queue-num 123
sudo iptables -D INPUT -p tcp -j NFQUEUE --queue-num 321
sudo iptables --flush
