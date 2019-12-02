USER_INCLUDES = \
	-I./libbpf/src/build/usr/include/ \
	-I./libbpf/include/ \
	-I./src/headers
SRC_DIR = ./src/common


user: user_packet_trainer

user_packet_trainer: common_user_bpf_xdp.o common_params.o
	cc -g -Wall $(USER_INCLUDES) \
	-L$(LIBBPF_DIR) \
	 $(OBJECT_DIR)/common_user_bpf_xdp.o \
	 $(OBJECT_DIR)/common_params.o \
	 -o $(BUILD_DIR)/user_packet_trainer \
	 src/user/xdp_packet_trainer.c \
	 $(LDLIBS)

stat:
	./build/user_packet_trainer
