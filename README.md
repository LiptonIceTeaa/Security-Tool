# Network and Website Vulnerability Scanner Tool

## Description
The Network and Website Vulnerability Scanner Tool is a comprehensive solution designed for network administrators and developers to identify and understand vulnerabilities within their network infrastructure and websites. 
This versatile tool includes two key components: a Network Scanner and a Website Scanner. Both components provide detailed reports, allowing users to assess potential risks and improve security measures.

### Features
1. Network Scanner
- The Network Scanner component enables users to scan machines within a network. It offers the following features:
- Scan Machines and Ports: Scans specified machines in a network and reports open ports, along with descriptions and known vulnerabilities associated with each port.
- Detailed Reports: Provides a detailed report, allowing network administrators to gain insights into vulnerabilities and exposed surfaces.
-- How to Use Network Scanner
To run the Network Scanner, provide the machine(s) address and port number(s) as input. The tool will generate a comprehensive report with vulnerability details.
Example Command:
        python NetworkScanner.py -m <machine_address> -p <port_number>
2. Website Scanner
- The Website Scanner component focuses on identifying web vulnerabilities, such as XSS (Cross-Site Scripting) and command injection. It includes the following functionalities:
- Automated Scans: Carries out automated scans on specified website addresses, checking for vulnerabilities.
- Extensible Framework: Allows developers to add methods for detecting various vulnerabilities, enhancing the tool's flexibility.
- Web Crawler: Utilizes a built-in web crawler to perform a comprehensive scan of all links within the provided website, identifying errors and vulnerabilities.

### Usage Guidelines
- Network Scanner: Use the Network Scanner to assess network security, providing machine addresses and port numbers as input.
- Website Scanner: Employ the Website Scanner to evaluate web vulnerabilities. Developers can extend its functionality for specific vulnerabilities.

### Contributions
Contributions to this vulnerability scanner tool are welcome! Developers can enhance the tool by adding new vulnerability detection methods or improving existing ones.


Note: This README provides an overview of the Network and Website Vulnerability Scanner Tool. 
Detailed usage instructions and specific configurations may vary based on the project's implementation details.
This is a tool intended for educational purposes.





