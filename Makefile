build:
	docker build -t openxvpn -t openxvpn:dev .

push: build
	docker push openxvpn:dev

run: build
	docker run --rm -it -p 80:80 \
	        -v ./user.pw:/config/user.pw:ro \
	        -v ./ip2location.io.key:/config/ip2location.io.key:ro \
			-e OPEN_VPN_USER_PASS_PATH=/config/user.pw \
			-e IP2LOCATION_IO_KEY_FILE=/config/ip2location.io.key \
			--device=/dev/net/tun:/dev/net/tun \
			--cap-add=NET_ADMIN --privileged \
					openxvpn:dev
