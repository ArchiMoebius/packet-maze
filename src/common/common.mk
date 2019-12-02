COMMON_INCLUDES = \
	-I./libbpf/src/build/usr/include/ \
	-I./libbpf/include/ \
	-I./headers
SRC_DIR = ./src/common

common: xdp_loader

common_libbpf.o: $(SRC_DIR)/libbpf.c
	cc -g -Wall $(COMMON_INCLUDES) \
	-c -o $(OBJECT_DIR)/$@ \
	$<

common_params.o: $(SRC_DIR)/params.c
	cc -g -Wall $(COMMON_INCLUDES) \
	-c -o $(OBJECT_DIR)/$@ \
	$<

common_user_bpf_xdp.o: $(SRC_DIR)/user_bpf_xdp.c
	cc -g -Wall $(COMMON_INCLUDES) \
	-c -o $(OBJECT_DIR)/$@ \
	$<

xdp_loader: common_libbpf.o common_params.o common_user_bpf_xdp.o
	cc -g -Wall $(COMMON_INCLUDES) \
	-L$(LIBBPF_DIR) \
	-o ./build/xdp_loader \
		$(OBJECT_DIR)/common_libbpf.o \
		$(OBJECT_DIR)/common_params.o \
		$(OBJECT_DIR)/common_user_bpf_xdp.o \
		$(SRC_DIR)/$@.c \
		$(LDLIBS)
