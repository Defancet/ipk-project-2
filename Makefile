.PHONY = all clean
CXX = g++
TARGET=ipk-sniffer

all: $(TARGET)

hinfosvc: hinfosvc.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@

clean:
	rm -rf *.o $(TARGET)