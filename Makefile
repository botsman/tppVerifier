
MONGO_URL=mongodb://localhost:27017/
MONGO_DB=tpp

start_server:
	MONGO_URL=$(MONGO_URL) MONGO_DB=$(MONGO_DB) go run server/run.go

test:
	go test ./...
