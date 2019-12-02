CLANG ?= clang
LLC ?= llc
LIBBPF_DIR = ./libbpf/src
BUILD_DIR = ./build
OBJECT_DIR = $(BUILD_DIR)/.obj
OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a

LDFLAGS ?= -L$(LIBBPF_DIR)

ARCH := $(subst x86_64,x86,$(shell arch))

BIN := kernel user common

CLANG_FLAGS = -I$(LIBBPF_DIR)/build/usr/include -I$(LIBBPF_DIR)/ -g -I ./src \
        -D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
        -D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types \
        -Wno-gnu-variable-sized-type-not-at-end \
        -Wno-address-of-packed-member -Wno-tautological-compare \
        -Wno-unknown-warning-option  \
        -O2 -emit-llvm

LDLIBS := -lelf -l:libbpf.a

all: build $(OBJECT_LIBBPF) $(BIN)
	ulimit -l 1024

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
		mkdir -p $(BUILD_DIR)/.obj ; \
	fi

clean-all: clean
	rm -rf $(LIBBPF_DIR)/build
	$(MAKE) -C $(LIBBPF_DIR) clean

clean:
	rm -f $(BIN)
	rm -f *.ll
	rm -f *~
	rm -rf $(BUILD_DIR)

include src/common/common.mk
include src/user/user.mk
include src/kern/kern.mk
include src/python/python.mk
