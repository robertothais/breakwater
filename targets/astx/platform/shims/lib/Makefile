CC = gcc
CFLAGS_BASE = -Wall -Wextra -fPIC -shared -O2
CFLAGS_32 = $(CFLAGS_BASE) -m32
CFLAGS_64 = $(CFLAGS_BASE) -m64
LIBS = -ldl

# 32-bit targets
NETLINK_TARGET_32 = libnetlink_shim32.so
SPOOF_TARGET_32 = libconnection_spoof32.so
EXEC_TARGET_32 = libexec_tracer32.so

# 64-bit targets
NETLINK_TARGET_64 = libnetlink_shim64.so
SPOOF_TARGET_64 = libconnection_spoof64.so
EXEC_TARGET_64 = libexec_tracer64.so

# Source files
NETLINK_SOURCE = netlink_shim.c
SPOOF_SOURCE = connection_spoof.c
EXEC_SOURCE = exec_tracer.c

# All targets
ALL_TARGETS = $(NETLINK_TARGET_32) $(NETLINK_TARGET_64) $(SPOOF_TARGET_32) $(SPOOF_TARGET_64) $(EXEC_TARGET_32) $(EXEC_TARGET_64)

.PHONY: all clean

all: $(ALL_TARGETS)

# 32-bit builds
$(NETLINK_TARGET_32): $(NETLINK_SOURCE)
	$(CC) $(CFLAGS_32) -o $@ $< $(LIBS)
	@echo "Built $(NETLINK_TARGET_32) (32-bit)"

$(SPOOF_TARGET_32): $(SPOOF_SOURCE)
	$(CC) $(CFLAGS_32) -o $@ $< $(LIBS)
	@echo "Built $(SPOOF_TARGET_32) (32-bit)"

# 64-bit builds
$(NETLINK_TARGET_64): $(NETLINK_SOURCE)
	$(CC) $(CFLAGS_64) -o $@ $< $(LIBS)
	@echo "Built $(NETLINK_TARGET_64) (64-bit)"

$(SPOOF_TARGET_64): $(SPOOF_SOURCE)
	$(CC) $(CFLAGS_64) -o $@ $< $(LIBS)
	@echo "Built $(SPOOF_TARGET_64) (64-bit)"

$(EXEC_TARGET_32): $(EXEC_SOURCE)
	$(CC) $(CFLAGS_32) -o $@ $< $(LIBS)
	@echo "Built $(EXEC_TARGET_32) (32-bit)"

$(EXEC_TARGET_64): $(EXEC_SOURCE)
	$(CC) $(CFLAGS_64) -o $@ $< $(LIBS)
	@echo "Built $(EXEC_TARGET_64) (64-bit)"

clean:
	rm -f $(ALL_TARGETS)
