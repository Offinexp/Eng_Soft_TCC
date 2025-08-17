import base64

caminho_arquivo = r"C:\Users\Fernanda\Desktop\teste.mp4" # o r antes da string evita problemas com barras

with open(caminho_arquivo, 'rb') as f:
    arquivo_binario = f.read()

arquivo_base64 = base64.b64encode(arquivo_binario).decode('utf-8')

print(arquivo_base64)
