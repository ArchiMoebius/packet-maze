kernel: kern_packet_trainer.o kern_packet_drop.o

kern_packet_trainer.o: src/kern/xdp_packet_trainer.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o - |      \
        $(LLC) -march=bpf -mcpu=$(CPU) -filetype=obj -o $(BUILD_DIR)/$@

kern_packet_drop.o: src/kern/xdp_packet_drop.c
	$(CLANG) $(CLANG_FLAGS) -Os -c $< -o - |      \
        $(LLC) -march=bpf -mcpu=$(CPU) -filetype=obj -o $(BUILD_DIR)/$@

train:
	./build/xdp_loader -d lo -S --filename ./build/kern_packet_trainer.o
train-remove:
	./build/xdp_loader -U -d lo -S --filename ./build/kern_packet_trainer.o
	unlink /sys/fs/bpf/lo/ipv4hashmap
drop:
	./build/xdp_loader -d lo -S --filename ./build/kern_packet_drop.o
drop-remove:
	./build/xdp_loader -U -d lo -S --filename ./build/kern_packet_drop.o
