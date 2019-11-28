CLANG ?= clang
LLC ?= llc
LIBBPF_DIR = ./libbpf/src
BUILD_DIR = ./build

OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a

LDFLAGS ?= -L$(LIBBPF_DIR)

ARCH := $(subst x86_64,x86,$(shell arch))

BIN := kern_packet_trainer.o user_packet_trainer xdp_loader
CLANG_FLAGS = -I$(LIBBPF_DIR)/build/usr/include -g -I ./src \
        -D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
        -D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types \
        -Wno-gnu-variable-sized-type-not-at-end \
        -Wno-address-of-packed-member -Wno-tautological-compare \
        -Wno-unknown-warning-option  \
        -O2 -emit-llvm

LDLIBS := -lelf -l:libbpf.a

all: build $(OBJECT_LIBBPF) common $(BIN) load

$(OBJECT_LIBBPF): 
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) && $(MAKE) all; \
  	mkdir -p build; DESTDIR=build $(MAKE) install_headers; \
	fi

build:
	@if [ ! -d $(BUILD_DIR) ]; then \
		mkdir $(BUILD_DIR) ; \
	fi

common:
	gcc -g -Wall -I./libbpf/src/build/usr/include/  -I./headers -c -o $(BUILD_DIR)/common_libbpf.o src/common/common_libbpf.c
	gcc -g -Wall -I./libbpf/src/build/usr/include/  -I./headers -c -o $(BUILD_DIR)/common_params.o src/common_params.c
	gcc -g -Wall -I./libbpf/include/ -I./libbpf/src/build/usr/include/ -L./libbpf/src/ -I./headers -c -o $(BUILD_DIR)/common_user_bpf_xdp.o src/common_user_bpf_xdp.c

xdp_loader:
	cc -Wall -I./libbpf/src//build/usr/include/ -g -I./headers/ -L./libbpf/src/ -o ./build/xdp_loader \
		./build/common_libbpf.o ./build/common_params.o ./build/common_user_bpf_xdp.o \
		src/xdp_loader.c -l:libbpf.a -lelf


kern_packet_trainer.o: src/kern/xdp_packet_trainer.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o - |      \
        $(LLC) -march=bpf -mcpu=$(CPU) -filetype=obj -o $(BUILD_DIR)/$@

user_packet_trainer:
	cc -Wall -I./libbpf/src//build/usr/include/ -g -I./src/headers/ -L./libbpf/src/ -o $(BUILD_DIR)/user_packet_trainer src/user/xdp_packet_trainer.c

clean-all:
	rm -rf $(LIBBPF_DIR)/build
	$(MAKE) -C $(LIBBPF_DIR) clean
	clean

clean:
	rm -f $(BIN) 
	rm -f *.ll
	rm -f *~
	rm -rf $(BUILD_DIR)

load:
	./build/xdp_loader -d enp8s0 -S --filename ./build/kern_packet_trainer.o
remove:
	./build/xdp_loader -U -d enp8s0 -S --filename ./build/kern_packet_trainer.o
