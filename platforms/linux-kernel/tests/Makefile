CC      ?= gcc
CFLAGS  := -Wall -Wextra -I../include
TARGET  := user_ioctl_test

all: $(TARGET) policy_test

$(TARGET): user_ioctl_test.c
	$(CC) $(CFLAGS) -o $@ $<

policy_test: policy_test.c ../src/policy.h ../include/uapi/aivpn.h
	$(CC) -Wall -Wextra -o $@ policy_test.c

policy-test: policy_test
	./policy_test

test: $(TARGET)
	@echo "NOTE: requires aivpn.ko loaded and root privileges"
	sudo ./$(TARGET)

clean:
	rm -f $(TARGET) policy_test

.PHONY: all test clean policy-test
