#!/usr/bin/bash

source /home/projeta/.bashrc
lstart Serveur Serveur2 Serveur3 Serveur4 Serveur5
vstart Routeur --eth0=tap,10.0.0.1,10.0.0.2 --eth1=H2 --mem=128
route add -net 192.168.2.0/24 gw 10.0.0.2

# A mettre sur Routeur : ifconfig eth1 192.168.2.1
