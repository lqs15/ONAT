# ONAT
*ONAT: Offloading elephant flows' rule from NAT server to switch*

ONAT serves as a NAT server, and offloads elephant flows' NAT mappings to switch in real time. Simulated_nat.cpp simulates a switch locally, and nat.cpp could make RPC communication with your switch.

# Run

g++ simulated_nat.cpp -std=c++0x -lpcap -lpthread -o simulated_nat

