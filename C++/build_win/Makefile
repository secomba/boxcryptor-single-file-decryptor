# Specify compiler options
INCLUDES = -I"../cryptopp/include" 
#LIBRARIES = -L"../cryptopp/lib/debug"
CPPFLAGS = -std=c++11
#CPPFLAGS = /MT
CPP = g++

# All libs
LIBS = ../cryptopp/lib/debug/libcryptopp.a
#LIBS = ../cryptopp/lib/release/libcryptopp.a

# Specify source dir
SOURCE = ../

# Target name
TARGET = bc-file-decryptor.exe

.PHONY: all
all: $(TARGET)

# Link the object files into a binary
$(TARGET): compile
	$(CPP) $(CPPFLAGS) -o $(TARGET) *.o $(LIBS)
	
# Compile the source files into object files
compile:
	$(CPP) $(CPPFLAGS) $(INCLUDES) -c $(SOURCE)*.cpp

# Clean target
clean:
	del $(OBJS) $(TARGET).exe