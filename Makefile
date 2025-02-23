# Use Bash instead of Dash
SHELL := /bin/bash

# Compiler settings
CC = gcc
CFLAGS = -Wall -Wextra -Werror -g -O0
LDFLAGS = -lcrypto -lssl
BUILD_DIR = build
LOGFILE = $(BUILD_DIR)/build.log

# Targets
TARGETS = $(BUILD_DIR)/client $(BUILD_DIR)/server
OBJECTS = $(BUILD_DIR)/md5_utils.o $(BUILD_DIR)/crypto_utils.o

# Ensure build directory exists
$(shell mkdir -p $(BUILD_DIR))

# Default target
all: clean_log $(TARGETS)
	@echo "✅ Build successful!" | tee -a $(LOGFILE)
	./apply_setcap.sh 2>> $(LOGFILE)

# Build client
$(BUILD_DIR)/client: client.c $(OBJECTS)
	@echo "🔨 Building client..." | tee -a $(LOGFILE)
	@if $(CC) $(CFLAGS) -o $@ client.c $(OBJECTS) $(LDFLAGS) 2> >(tee -a $(LOGFILE) >&2); then \
		echo "✅ Client build successful!" | tee -a $(LOGFILE); \
	else \
		echo "❌ Client build failed! Check $(LOGFILE) for details." | tee -a $(LOGFILE); \
		exit 1; \
	fi

# Build server
$(BUILD_DIR)/server: server.c $(OBJECTS)
	@echo "🔨 Building server..." | tee -a $(LOGFILE)
	@if $(CC) $(CFLAGS) -o $@ server.c $(OBJECTS) $(LDFLAGS) 2> >(tee -a $(LOGFILE) >&2); then \
		echo "✅ Server build successful!" | tee -a $(LOGFILE); \
	else \
		echo "❌ Server build failed! Check $(LOGFILE) for details." | tee -a $(LOGFILE); \
		exit 1; \
	fi

# Build md5_utils
$(BUILD_DIR)/md5_utils.o: md5_utils.c md5_utils.h
	@echo "🔨 Compiling md5_utils..." | tee -a $(LOGFILE)
	@if $(CC) $(CFLAGS) -c md5_utils.c -o $@ 2> >(tee -a $(LOGFILE) >&2); then \
		echo "✅ md5_utils compilation successful!" | tee -a $(LOGFILE); \
	else \
		echo "❌ md5_utils compilation failed! Check $(LOGFILE) for details." | tee -a $(LOGFILE); \
		exit 1; \
	fi

# Build crypto_utils (for encryption)
$(BUILD_DIR)/crypto_utils.o: crypto_utils.c crypto_utils.h
	@echo "🔨 Compiling crypto_utils..." | tee -a $(LOGFILE)
	@if $(CC) $(CFLAGS) -c crypto_utils.c -o $@ 2> >(tee -a $(LOGFILE) >&2); then \
		echo "✅ crypto_utils compilation successful!" | tee -a $(LOGFILE); \
	else \
		echo "❌ crypto_utils compilation failed! Check $(LOGFILE) for details." | tee -a $(LOGFILE); \
		exit 1; \
	fi

# Clean log file before each build
clean_log:
	@echo "📝 Cleaning previous log..." > $(LOGFILE)

# Clean target
clean:
	@echo "🧹 Cleaning build directory..." | tee -a $(LOGFILE)
	rm -rf $(BUILD_DIR)
