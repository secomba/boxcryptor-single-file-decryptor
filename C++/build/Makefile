# Specify compiler options
INCLUDES = -I../cryptopp/include
CFLAGS = -Wall -g -std=c++17
CC = g++

# All objs
OBJECTS = main.o AccountData.o AESHelper.o Base64Helper.o FileData.o HashHelper.o PBKDF2Helper.o RSAHelper.o

# All libs
LDFLAGS = -L../cryptopp/lib/debug -static -lcryptopp

# Specify source dir
SOURCE = ../

# Target name
TARGET = bc-file-decryptor.out

.PHONY: all
all: $(TARGET)

# Link the object files into a binary
$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS) 
	
# Compile the source files into object files
%.o: $(SOURCE)%.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

# Clean target
clean:
	rm -f $(OBJECTS) $(TARGET)
