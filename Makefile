GENFILE=./build/gen.go
BINARY=packet_tracer
BUILD_DIRECTORY=./build
ENTRY_POINT=./cmd/main.go
.PHONY: build

build:
	go build -o $(BINARY) $(ENTRY_POINT)
	mv $(BINARY) $(BUILD_DIRECTORY)
gen:
	go generate $(GENFILE)
run:
	$(BUILD_DIRECTORY)/$(BINARY)
clean:
	yes | rm $(BUILD_DIRECTORY)/*.o \
	$(BUILD_DIRECTORY)/main_x86_bpfel.go \
	$(BUILD_DIRECTORY)/$(BINARY)
