# XPATH injection

## Description

XPATH Injection Tester is a comprehensive tool designed for security professionals and ethical hackers to test and exploit XPath injection vulnerabilities in web applications. This tool allows users to systematically identify and exploit weaknesses in XPath queries that applications use to interact with their XML data stores. By simulating both common and advanced XPath injection attacks, users can evaluate the robustness of web applications against such vulnerabilities, thereby enhancing their security posture. 
## Features

- Capable of retrieving extensive data from vulnerable systems.
- Utilizes trees and maps for efficient data management.
- Integrated with essential libraries like sys, signal, time, requests, string, argparse, and pwn for enhanced functionality.
- Builts autmatically the dumped XML.

## Installation

```bash
git clone https://github.com/Hamibubu/XPATHi.git
cd XPATHi
pip install -r requirements.txt
```

## Usage

1. Adequate the payload to your POST request if needed.
2. Run the following command
```bash
python3 autoXPATH.py -u http://<your endpoint> -d <the depth needed>
```