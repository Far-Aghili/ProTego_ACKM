#!/bin/bash
echo "Starting Vault"
cd /home/
./vault server -config=config3.hcl &
sleep 2
export VAULT_ADDR='http://127.0.0.1:8200'
./vault status > temp.txt
sleep 1
s=$(grep "Sealed " temp.txt | sed -e 's/.* //')
if [ "$s" != "false" ]
then
	./vault operator init >> keys.txt
	sleep 3
	x=$(grep "Unseal Key 1:" keys.txt | sed -e 's/.*://')
	y=$(grep "Unseal Key 2:" keys.txt | sed -e 's/.*://')
	z=$(grep "Unseal Key 3:" keys.txt | sed -e 's/.*://')
	./vault operator unseal $x
	sleep 3
	./vault operator unseal $y
	sleep 3
	./vault operator unseal $z
	sleep 3
	m=$(grep "Initial Root Token:" keys.txt | sed -e 's/.*://')
	./vault login $m
	sleep 3
	./vault secrets enable transit
else
        echo 'yes'
fi       
echo "Starting Server"
cd /home/KUL-ACL/
python3 main.py 
sleep 1
echo "waiting for the client request"
sleep infinity
