.PHONY = all clean
CXX = g++
TARGET = ipk-sniffer
LIBS = -lpcap

all: $(TARGET)

$(TARGET): $(TARGET).cpp
	$(CXX) $(CXXFLAGS) $< $(LIBS) -o $@

clean:
	rm -rf *.o $(TARGET)