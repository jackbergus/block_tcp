#!/bin/sh
sudo iptables -A OUTPUT -p tcp -j NFQUEUE --queue-num 123
sudo iptables -A INPUT -p tcp -j NFQUEUE --queue-num 321
sudo block_tcp
