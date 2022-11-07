# Buffer-overflow
##This git will analyze software vulnerabilities such as “buffer overflow” and prevent their exploitation.
A program vulnerable to “buffer overflow” was developed that takes a string as an argument and copies it to the buffer, a program was also developed that, according to the known size of the buffer of the vulnerable program, assembles the return address and the shell code and then launches the vulnerable program, passing as argument to the generated input string that causes a buffer overflow and deletion of the given registry key.
