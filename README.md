
# GoBrrp - Full Proxy Tool for Game Hacking

*GoBrrp* is a network traffic interception tool specifically designed for Game Hacking purposes. It will intercept each and every packet and let the user decide how to parse the packets depending on the protocol.


### Project Structure

 - `src/certs`   **Certificates that are created by the module.**
 - `src/core` **Bulk of the implementation lies here.**
 - `src/test` **Test code for some features.**
 - `src/configs`**Config files can only be read in *yaml* format and must follow certain criteria.**
 
### Running

    cd src
    go run main.go

