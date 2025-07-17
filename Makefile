build:
	docker build -t openxvpn -t openxvpn:dev .

push: build
	docker push openxvpn:dev

run: build
	docker run --rm -it -p 80:80 \
	        -v ./user.pw:/config/user.pw:ro \
			-e OPEN_VPN_USER_PASS_PATH=/config/user.pw \
			--cap-add=NET_ADMIN --privileged \
					openxvpn:dev
