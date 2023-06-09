all:
# change file permission
	chmod +x mitm_attack pharm_attack
# enable ip forwarding
	sudo sysctl -w net.ipv4.ip_forward=1
# generate RSA key with OpenSSL and save it in file key.pem
	openssl genrsa -out key.pem 4096
# generate certificate with RSA key
	openssl req -new -x509 -days 1826 -key key.pem -out ca.crt -subj '/C=TW/O=NYCU/CN=chieh.yun'
# flush nat IP table
	sudo iptables -t nat -F
# set IP tables redirect rule
	sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443
# create a directory to store sslsplit log
	mkdir -p sslsplit_log

clean:
# remove key.pem, ca.crt, connect.log
	-rm -f key.pem ca.crt connect.log
# remove sslspilt_log folder
	-rm -rf sslsplit_log/
