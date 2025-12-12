#!/bin/bash

echo "[*] Setting NAT rules..."
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -X
sudo iptables -t nat -X

sudo iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE
sudo iptables -A FORWARD -i wlx24ec99bfece2 -o enp0s3 -j ACCEPT
sudo iptables -A FORWARD -i enp0s3 -o wlx24ec99bf3c32 -m state --state RELATED,ESTABLISHED -j ACCEPT


echo "[*] Killing interfering processes..."
sudo airmon-ng check kill

echo "[*] Starting inerface up..."
sudo ip link set wlx24ec99bfece2 up

echo "[Setting static IP on interface..."
sudo ip addr flush dev wlx24ec99bfece2
sudo ip addr add 10.0.0.1/24 dev wlx24ec99bfece2

echo "[*] Starting hostapd..."
sudo hostapd /etc/hostapd/hostapd.conf
