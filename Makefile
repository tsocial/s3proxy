SHELL = bash
SERVER_REPO := "tsl8/s3proxy"

deps:
	dep version || (curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh)
	dep ensure -v

test:
	env GOCACHE=/tmp/gocache go test -v -race ./...

build:
	env GOCACHE=/tmp/gocache GOOS=linux CGO_ENABLED=0 go build -ldflags "-X main.date=$(shell date +%Y-%m-%d-%H:%M:%S)" -o s3proxy -a -installsuffix cgo .

docker_up: build
	docker-compose -f docker-compose.yaml up -d

docker_down:
	docker-compose -f docker-compose.yaml down

build_image: build
	docker-compose -f docker-compose.yaml build

docker_login:
	echo "$(DOCKER_PASSWORD)" | docker login -u "$(DOCKER_USERNAME)" --password-stdin

upload_image: docker_login build_image
	docker tag $(SERVER_REPO):latest $(SERVER_REPO):$(TRAVIS_BRANCH)-latest
	docker tag $(SERVER_REPO):latest $(SERVER_REPO):$(TRAVIS_BRANCH)-$(TRAVIS_BUILD_NUMBER)
	docker push $(SERVER_REPO):latest
	docker push $(SERVER_REPO):$(TRAVIS_BRANCH)-latest
	docker push $(SERVER_REPO):$(TRAVIS_BRANCH)-$(TRAVIS_BUILD_NUMBER)
