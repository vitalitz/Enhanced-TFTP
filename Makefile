# Compiler settings
CC = gcc
CFLAGS = -Wall -Wextra -O2
BUILD_DIR = build
LOGFILE = $(BUILD_DIR)/build.log

# Targets
TARGETS = $(BUILD_DIR)/client $(BUILD_DIR)/server
OBJECTS = $(BUILD_DIR)/md5_utils.o

# Ensure build directory exists
$(shell mkdir -p $(BUILD_DIR))

# Default target
all: $(TARGETS)

# Build client
$(BUILD_DIR)/client: client.c $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ client.c $(OBJECTS) 2>&1 | tee -a $(LOGFILE)

# Build server
$(BUILD_DIR)/server: server.c $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ server.c $(OBJECTS) 2>&1 | tee -a $(LOGFILE)

# Compile md5_utils.c
$(BUILD_DIR)/md5_utils.o: md5_utils.c md5_utils.h
	$(CC) $(CFLAGS) -c md5_utils.c -o $@ 2>&1 | tee -a $(LOGFILE)

# Clean target
clean:
	rm -rf $(BUILD_DIR)