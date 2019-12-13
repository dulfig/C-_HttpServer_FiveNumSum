# C-_HttpServer_FiveNumSum
A C++ http server that uses black box techniques with an R application to retrieve the five number summary of entered values

## Running
Requires a linux based system and two terminal windows  </br></br>
First run somRApp  
`$ chmod u+x somRApp`  
`$ ./somRApp --port=12345`  </br></br>
Second run the simpleHttpServer.cpp  
`$ g++ simpleHttpServer.cpp JSONValue.cpp -o simpleHttpServer -lpthread -g`  
`$ ./simpleHttpServer 14321 12345`  </br></br>
If using a VM or server you will requrie a third window to test using ProjTester.java    
`$ javac ProjTester.java`   
`$ java ProjTester http://127.0.0.1:14321`  
Using Java will produce the expected raw html code since you would not have access to browser via certain servers
## Protocol representation
```             client HTTP                 JSON request               R 
+---------+  ---------->  +-----------+  ------------>  +-------+  --->  +---+
| browser |               |http server|                 |somRApp|        | R |
|         |  server HTML  |           |  JSON response  |       |   R    |   |
+---------+  <----------  +-----------+  <------------  +-------+  <---  +---+
```
## Example Plot Response from R
!(https://github.com/dulfig/C-_HttpServer_FiveNumSum/blob/master/plot.png)
