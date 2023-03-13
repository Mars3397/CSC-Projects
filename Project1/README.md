# Project 1

<aside>
📌 **Links**

- [What is IPsec?](https://aws.amazon.com/tw/what-is/ipsec/)
- [What is ESP?](http://www.tsnien.idv.tw/Manager_WebBook/chap10/10-4%20IPSec%20ESP%20安全協定.html)
- [What is sockaddr_ll?](https://man7.org/linux/man-pages/man7/packet.7.html)
</aside>

### Little Tricks

- **Ubuntu Software 打不開的解法**
    
    ```bash
    sudo rm -rvf /var/lib/apt/lists/*
    sudo apt-get update
    sudo shutdown -p now
    ```
    
- **Cirtual Box Full Screen Size**
    - Click “Device” on the bar → click “Insert Guest Additions CD Image”
    - Return to VM desktop → scroll down the side bar to find a CD icon → open it and click “run software” on the top right
- **Install VScode**
    - Click “Ubuntu Software” → search for VScode → Install

### VM Installation

- Download the [VM image](https://nas.nems.cs.nctu.edu.tw:5001/sharing/h4dv3uN6b)
- Open Virtual Box → 工具 → 加入 → 把新下載的 image 加進來
- 新增 → 類型選「Linux」→ 版本選「Ubuntu (64-bit)」→ 下一步
    
    → 記憶體、CPU 預設即可（也可稍微調大） → 下一步
    
    → Select “Use an Existing Virtual Hard Disk File” → 選剛剛下載的那個 → 下一步
    
    → Finish
    
- 到「檔案 File」→「工具」開起「Network Manager」
- 建立一個 Host-only 的網卡 → 把這張加到 VM 的網路介面卡 2
- 然後複製一台 VM，一台是 server，另一台是 client

### Understanding

- 每一個 `xxx.h, xxx.c` 都會定義某一層或是某種用途的資料結構，然後我們需要在 xxx.c 裡面實作出這個資料結構的一些 function
    - `dev.h`, `dev.c` → 定義 link layer 的相關操作
    - `net.h`, `net.c` → 定義 Network 層的相關資訊跟操作，像是 src/dst IP address 和 dissect_ip（可以分解出 packet information） 之類的
    - `esp.h`, `esp.c` → 定義 [ESP](http://www.tsnien.idv.tw/Manager_WebBook/chap10/10-4%20IPSec%20ESP%20安全協定.html) 的相關資訊跟操作，像是 AH 和 get_key, dissect_esp（可以分解出 esp information）
    - `trasport.h`, `transport.c` → 定義 TCP 層相關的資訊跟操作，像是 src/dst port, seq/ack number 和 dissect_tcp（可以分解出 tcp information）

### Network Setting

- How to know my IP → `ifconfig`: the IP in second network interface is the IP used to fill in `.sh` file
    - Second network interface 是新加的那張 hostonly 網卡 → 會用來溝通 server, client 的
    
- 改完之後 run spec p.13 的 command → client 會一直送 hahaha 給 server