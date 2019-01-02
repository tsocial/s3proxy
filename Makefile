SHELL = bash
SERVER_REPO := "tsl8/s3proxy"

docker_up:
	docker-compose -f docker-compose.yaml up -d

docker_down:
	docker-compose -f docker-compose.yaml down

build_image:
	docker-compose -f docker-compose.yaml build

docker_login:
	echo "$(DOCKER_PASSWORD)" | docker login -u "$(DOCKER_USERNAME)" --password-stdin

upload_image: docker_login
	docker tag $(SERVER_REPO):latest $(SERVER_REPO):$(TRAVIS_BRANCH)-latest
	docker tag $(SERVER_REPO):latest $(SERVER_REPO):$(TRAVIS_BRANCH)-$(TRAVIS_BUILD_NUMBER)
	docker push $(SERVER_REPO):latest
	docker push $(SERVER_REPO):$(TRAVIS_BRANCH)-latest
	docker push $(SERVER_REPO):$(TRAVIS_BRANCH)-$(TRAVIS_BUILD_NUMBER)
