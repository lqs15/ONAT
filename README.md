# ONAT

*ONAT: Offloading elephant flows' rule from NAT server to switch*

ONAT serves as a NAT server, and offloads elephant flows' NAT mappings to switch in real time. Simulated_nat.cpp simulates a switch locally, and nat.cpp could make RPC communication with your switch.

## Install Environment

1. Create environment

    ```
    conda create -n NAT python=3.7.5 scapy
    ```

    ```
    conda activate NAT
    ```

3. Install other dependencies

    ```
    conda install pip
    ```

    ```
    pip install -i https://pypi.tuna.tsinghua.edu.cn/simple argparse netaddr
    ```

## Run

1. Run command

    (in one terminal)
    ```
    python3 python run.py -d
    ```
    (open another seperate terminal)
    ```
    g++ nat.cpp -std=c++0x -lpcap -lpthread -o main
    ```
    
    ```
    sudo ./main
