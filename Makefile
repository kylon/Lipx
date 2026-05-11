.PHONY: clean

PROJECT = lipx
C_SOURCES = IPSPatch.c main.c

override CFLAGS += -O3 -std=gnu11

all: $(PROJECT)

$(PROJECT): $(C_SOURCES)
	$(CC) $(CFLAGS) $(C_SOURCES) -o $(PROJECT)

clean:
	$(RM) $(PROJECT)
