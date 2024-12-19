fichier_txt = 'fichier1000.txt'

try:
    with open(fichier_txt, 'r', encoding='utf-8') as f:
        contenu = f.read()
        print(contenu)
except FileNotFoundError:
    print(f"Le fichier {fichier_txt} n'a pas été trouvé.")