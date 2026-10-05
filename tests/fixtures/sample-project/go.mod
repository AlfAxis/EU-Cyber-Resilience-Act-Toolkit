module example.com/sample-service

go 1.21

require github.com/gin-gonic/gin v1.7.0

require (
	github.com/Masterminds/semver/v3 v3.2.0 // indirect
	github.com/example/legacy v2.0.0+incompatible
	github.com/example/forked v1.0.0
	github.com/example/local v0.1.0
	golang.org/x/text v0.3.7 // indirect
)

replace github.com/example/forked => github.com/example/forked-fixed v1.0.1

replace (
	github.com/example/local => ../local
)

exclude golang.org/x/net v0.0.1
