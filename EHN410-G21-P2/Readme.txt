The program has a number of available parameters:
-e          encryption
-d          decryption
-cbc        <len>   cbc encryption/decryption
-cfb        <len>   cfb encryption/decryption
<len>       either 128, 192 or 256
-t          <text to decrypt>
-key        <password>
-iv         <initialization vector>
-fi         <input file>
-fo         <output file>
-streamlen  <len>    length of the stream ( for cfb: either 8, 64 or 128)
-h          help

Entering -e will tell the program to encrypt, while -d will tell the program to decrypt. 

Entering -cbc will tell the program to encrypt or decrypt using the Cipher Block Chaining
mode. When using this mode, it is not necessary to use the -streamlen parameter.

Entering -cfb will tell the program to encrypt or decrypt using the Cipher Feedback mode.
When using this mode, the -streamlen parameter can be used.

Directly after entering either -cbc or -cfb, enter the length of the key to be used (in 
number of bits). The numbers 128, 192 and 256 may be entered. 

Entering -t will tell the program to use the text following this parameter as the input 
for encryption/decryption. When this option is used, the program will encrypt/decrypt the 
input and print the output to the terminal in hexadecimal format. The text entered following 
this parameter must be enclosed in quotation marks if the text contains spaces. 

Entering -key will tell the program to use the argument after this parameter as the key
(secret password) for encryption/decryption.

Entering -iv will tell the program to use the next argument as the initialization vector
for encryption/decryption.

Entering -fi will tell the program to open a file and use it for encryption/decryption. 
To open the desired file, enter the full path to this file after entering the parameter. 
For example: -fi /home/user/documents/testpdf.pdf. 

Entering -fo will tell the program to use the next argument as the name for the output file.
For this argument, it is not necessary to specify the path, as the output will automatically 
be stored in either the CBC Output or CFB Output folder. Please enter the name of the output
file, preceded by "../". 
For example: -fo ../outputFile.pdf 

Entering the -streamlen parameter tells the program to use the following argument as the length
of the stream when using the cfb mode. If this argument is used with cbc mode, the program will 
return an error message. 

To test AES functionality, enter the following parameters: -e, <len>, -t, <text>, -k and <password>.
The program will then Output the AES functionality test. 

Entering the -h parameter will make the program print a help message to the terminal. 

To compile the program, open a terminal in the folder where the source files are located and 
enter the command "make". To run the program, enter "./main" followed by the desired arguments.

For example:
To encrypt a file using CBC:
./main -e -cbc 128 -fi /home/user/documents/testpdf.pdf -fo outputfile.pdf -key ThisIsTheKey 
-iv ThisIsTheIV

To encrypt a file using CFB:
./main -e -cfb 128 -fi /home/user/documents/testpdf.pdf -fo outputfile.pdf -key ThisIsTheKey 
-iv ThisIsTheIV -streamlen 8

To encrypt text:
./main -e -cbc 128 -t "this is the text" -key ThisIsTheKey -iv ThisIsTheIV 

To see the AES steps (subbytes, shifting rows etc):
./main -e 128 -t "This is the text" -key ThisIsTheKey 
