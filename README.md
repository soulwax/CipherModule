# Cipher Module (any Java backend)
### Proof of Concept! 
### You should know what you're doing when you intend to use this module.
### Mostly snippets embedded into CatCraft.
  
### Features:
  - Encrypts -args, outputs encrypted result into a log file. 
  - Authenticates a user using the current industry standard of salting and hash mapping.
  - Manual input method.
  - Creates a secure key pair server side
  - Encrypts and decrypts using said key pairs
  - The cipher is cached and garbage collected

### Arguments when not using manual input:
- argument 0: encryption method (SHA-256, MD5, SHA-1)
- argument 1: username
- argument 2: password
- argument 3...n: message to encrypt

When no args are given for execution, a manual input method will appear.

Supported encryption methods: SHA-256, SHA-1, MD5

Key Generator Method: DES


## Build Instructions

### IntelliJ Idea (recommended):
1. Open project root folder as -> Maven - click OK
2. Add Configuration -> Add New (+) -> choose: "Maven" from the list
3. Type in the "Command Line" option under "Parameters" -> "install" (without the "")
4. For code execution: mvn exec:java. You can add a separate configuration or use step 3 by appending it to the command line.

License: Public Domain
