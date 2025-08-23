CC = gcc
CFLAGS = -O2 -Wall -m32

TARGET = chrome
SOURCE = chrome.c
INSTALL_DIR = /usr/local/bin

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built $(TARGET)"

install: $(TARGET)
	mkdir -p $(INSTALL_DIR)
	cp $(TARGET) $(INSTALL_DIR)/
	@echo "Installed $(TARGET) to $(INSTALL_DIR)/"

clean:
	rm -f $(TARGET)