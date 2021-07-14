# Crypto Module (any Java backend)
### Warning: Experimental Code / Proof of Concept! Not yet intended for production use.
### You can't use it for anything useful unless you know what you're doing.
  
## Features:
Encrypts -args, outputs encrypted result into a log file.
Use: execute jar by giving the following args:

- argument 0: encryption method
- argument 1...x: message to encrypt with said method

Remove provided default maven argument, add no arguments for execution and you will be prompted to give the args
during execution.

Supported encryption methods: SHA-256, SHA-1, MD5

Key Generator Method: DES


## Build Instructions

### IntelliJ Idea (recommended):
1. Open project root folder as -> Maven - click OK
2. Add Configuration -> Add New (+) -> choose: "Maven" from the list
3. Type in the "Command Line" option under "Parameters" -> "install" (without the "")
4. For code execution: mvn exec:java. You can add a separate configuration or use step 3 by appending it to the command line.

License: copyrighted, permission for private non-commercial use is granted.

