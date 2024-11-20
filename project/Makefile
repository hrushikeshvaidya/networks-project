# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -Wall -std=c++11

# Targets
TARGETS = utils serverM serverA serverR serverD client

# Object files
OBJS_M = serverM.o
OBJS_A = serverA.o
OBJS_R = serverR.o
OBJS_D = serverD.o
OBJS_CLIENT = client.o
OBJS_UTILS = utils.o

# Build all executables
all: $(TARGETS)

# Compile utils
utils: $(OBJS_UTILS)
	$(CXX) $(CXXFLAGS) -c -o utils $(OBJS_UTILS)

# Compile and link serverM
serverM: $(OBJS_M)
	$(CXX) $(CXXFLAGS) -o serverM $(OBJS_M)

# Compile and link serverA
serverA: $(OBJS_A)
	$(CXX) $(CXXFLAGS) -o serverA $(OBJS_A)

# Compile and link serverR
serverR: $(OBJS_R)
	$(CXX) $(CXXFLAGS) -o serverR $(OBJS_R)

# Compile and link serverD
serverD: $(OBJS_D)
	$(CXX) $(CXXFLAGS) -o serverD $(OBJS_D)

# Compile and link client
client: $(OBJS_CLIENT)
	$(CXX) $(CXXFLAGS) -o client $(OBJS_CLIENT)

# Create object files from source files
utils.o: utils.cpp
	$(CXX) $(CXXFLAGS) -c utils.cpp

serverM.o: serverM.cpp
	$(CXX) $(CXXFLAGS) -c serverM.cpp

serverA.o: serverA.cpp
	$(CXX) $(CXXFLAGS) -c serverA.cpp

serverR.o: serverR.cpp
	$(CXX) $(CXXFLAGS) -c serverR.cpp

serverD.o: serverD.cpp
	$(CXX) $(CXXFLAGS) -c serverD.cpp

client.o: client.cpp
	$(CXX) $(CXXFLAGS) -c client.cpp

# Clean up
clean:
	rm -f *.o $(TARGETS)
