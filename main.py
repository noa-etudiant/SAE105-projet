import os
import csv
import re
import sys
import subprocess
import importlib

# Liste des bibliothèques requises
REQUIRED_LIBRARIES = [
    'matplotlib',
    'collections',  # Note: collections est un module standard de Python
]

def check_and_install_libraries():
    """
    Vérifie si les bibliothèques requises sont installées.
    Si une bibliothèque est manquante, tente de l'installer via pip.
    """
    missing_libraries = []

    for lib in REQUIRED_LIBRARIES:
        try:
            # Pour les modules standard comme collections, on passe
            if lib == 'collections':
                continue
            
            # Tente d'importer la bibliothèque
            importlib.import_module(lib)
        except ImportError:
            missing_libraries.append(lib)

    # Installation des bibliothèques manquantes
    if missing_libraries:
        print("Bibliothèques manquantes détectées. Tentative d'installation...")
        
        try:
            for lib in missing_libraries:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', lib])
                print(f"{lib} installée avec succès.")
        except subprocess.CalledProcessError:
            print(f"Erreur lors de l'installation des bibliothèques : {missing_libraries}")
            print("Veuillez les installer manuellement avec 'pip install <nom_bibliotheque>'")
            sys.exit(1)

# Appel de la fonction de vérification des bibliothèques avant l'exécution principale
check_and_install_libraries()

import matplotlib.pyplot as plt
from collections import Counter
from datetime import datetime

# Dossiers de sortie
RESULT_FOLDER = 'results'
os.makedirs(RESULT_FOLDER, exist_ok=True)

# Fonction pour convertir l'horodatage en secondes Unix
def convert_to_unix_timestamp(time_str):
    try:
        time_format = "%H:%M:%S.%f"
        current_time = datetime.strptime(time_str, time_format)
        epoch_time = datetime(1970, 1, 1)
        delta = current_time - epoch_time
        return delta.total_seconds()
    except ValueError:
        return None

# Fonction pour analyser chaque ligne du fichier texte
def parse_line(line):
    pattern = r"(\d{2}:\d{2}:\d{2}\.\d{6})\s+IP\s+([a-zA-Z0-9.-]+)(?:\.(\d+))?\s+>\s+([a-zA-Z0-9.-]+)(?:\.(\d+))?:"
    match = re.search(pattern, line)
    
    if match:
        timestamp = match.group(1)
        source_ip = match.group(2)
        dest_ip = match.group(4)
        
        unix_timestamp = convert_to_unix_timestamp(timestamp)
        
        if unix_timestamp is not None:
            return unix_timestamp, source_ip, dest_ip
    return None

# Fonction pour ajouter du "padding" aux valeurs
def pad_to_length(value, length=50):
    return str(value).ljust(length)

# Fonction pour remplacer ".ssh" par ".22" dans les adresses IP
def replace_ssh_with_22(ip_address):
    return ip_address.replace('.ssh', '.22')

# Fonction pour remplacer ".http" par ".80" dans les adresses IP
def replace_http_with_80(ip_address):
    return ip_address.replace('.http', '.80')

# Fonction pour analyser les vulnérabilités
def detect_vulnerabilities(source_ips, dest_ips):
    vulnerabilities = []
    
    ssh_attempts = [ip for ip in dest_ips if ".22" in ip]
    http_attempts = [ip for ip in dest_ips if ".80" in ip]
    
    if len(ssh_attempts) > 5:
        vulnerabilities.append("Tentatives multiples de connexion sur le port SSH détectées.")
    
    if len(http_attempts) > 5:
        vulnerabilities.append("Tentatives multiples de connexion sur le port HTTP détectées.")
    
    return vulnerabilities

# Fonction pour traiter le fichier et générer un fichier CSV avec les données
def process_file(input_file_path, output_file_path):
    source_ips = []
    dest_ips = []

    with open(input_file_path, 'r', encoding='utf-8') as infile, open(output_file_path, 'w', newline='', encoding='utf-8') as outfile:
        csv_writer = csv.writer(outfile, delimiter=';')
        csv_writer.writerow(['Horodatage Unix', 'IP Source', 'IP Destination'])

        for line in infile:
            result = parse_line(line)
            if result:
                source_ip = replace_http_with_80(replace_ssh_with_22(result[1]))
                dest_ip = replace_http_with_80(replace_ssh_with_22(result[2]))

                source_ips.append(source_ip)
                dest_ips.append(dest_ip)

                padded_result = [
                    pad_to_length(result[0], 50),
                    pad_to_length(source_ip, 50),
                    pad_to_length(dest_ip, 50)
                ]
                csv_writer.writerow(padded_result)

    create_graphs(source_ips, dest_ips)
    check_graph_files()
    vulnerabilities = detect_vulnerabilities(source_ips, dest_ips)
    return vulnerabilities

# Fonction pour créer les graphiques
def create_graphs(source_ips, dest_ips):
    source_ip_counts = Counter(source_ips)
    dest_ip_counts = Counter(dest_ips)

    plt.figure(figsize=(12, 8))
    plt.bar(source_ip_counts.keys(), source_ip_counts.values(), color='green')
    plt.xlabel('IP Source')
    plt.ylabel('Occurrences')
    plt.title('Occurrences des IP Source')
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.savefig(os.path.join(RESULT_FOLDER, 'source_ip_occurrences.png'))
    plt.clf()

    plt.figure(figsize=(12, 8))
    plt.bar(dest_ip_counts.keys(), dest_ip_counts.values(), color='red')
    plt.xlabel('IP Destination')
    plt.ylabel('Occurrences')
    plt.title('Occurrences des IP Destination')
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.savefig(os.path.join(RESULT_FOLDER, 'destination_ip_occurrences.png'))
    plt.clf()

# Vérifier si les graphiques ont été correctement créés
def check_graph_files():
    source_graph = os.path.join(RESULT_FOLDER, 'source_ip_occurrences.png')
    dest_graph = os.path.join(RESULT_FOLDER, 'destination_ip_occurrences.png')

    if not os.path.exists(source_graph):
        print("Erreur : Le graphique des IP Source n'a pas été créé.")
    else:
        print(f"Graphique des IP Source créé : {source_graph}")

    if not os.path.exists(dest_graph):
        print("Erreur : Le graphique des IP Destination n'a pas été créé.")
    else:
        print(f"Graphique des IP Destination créé : {dest_graph}")

# Fonction pour générer le fichier HTML avec les résultats
def generate_html(input_file, csv_file, vulnerabilities):
    vuln_message = "<p>Aucune vulnérabilité détectée.</p>"
    if vulnerabilities:
        vuln_message = "<ul>" + "".join([f"<li>{vuln}</li>" for vuln in vulnerabilities]) + "</ul>"
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Analyse des Trames</title>
        <style>
            body {{
                font-family: 'Roboto', sans-serif;
                background-color: #f7f7f7;
                margin: 0;
                padding: 0;
                color: #333;
            }}
            h1 {{
                background-color: #2980b9;
                color: white;
                padding: 20px;
                text-align: center;
                margin: 0;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }}
            h2 {{
                color: #27ae60;
                margin-bottom: 10px;
            }}
            h3 {{
                color: #e74c3c;
            }}
            .container {{
                width: 80%;
                margin: 20px auto;
                padding: 20px;
                background-color: white;
                box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
                border-radius: 10px;
            }}
            .section {{
                margin-bottom: 30px;
            }}
            img {{
                max-width: 100%;
                border-radius: 8px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }}
            a {{
                color: #2980b9;
                text-decoration: none;
                font-weight: bold;
            }}
            a:hover {{
                text-decoration: underline;
            }}
            ul {{
                padding-left: 20px;
                list-style-type: square;
            }}
            .result {{
                padding: 15px;
                background-color: #ecf0f1;
                border-radius: 8px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }}
            .result p {{
                font-size: 1.1em;
            }}
        </style>
    </head>
    <body>
        <h1>Analyse des Trames</h1>
        <div class="container">
            <div class="section">
                <h2>Résumé de l'analyse</h2>
                <p>Le fichier <code>{input_file}</code> a été analysé avec succès.</p>
            </div>

            <div class="section">
                <h2>Vulnérabilités détectées</h2>
                {vuln_message}
            </div>

            <div class="section">
                <h2>Téléchargement des résultats</h2>
                <p>Vous pouvez télécharger le fichier CSV contenant les données extraites : 
                <a href="{csv_file}" target="_blank">{csv_file}</a></p>
            </div>

            <div class="section">
                <h2>Graphiques</h2>
                <h3>Graphique des IP Source</h3>
                <img src="source_ip_occurrences.png" alt="Graphique des IP Source">
                
                <h3>Graphique des IP Destination</h3>
                <img src="destination_ip_occurrences.png" alt="Graphique des IP Destination">
            </div>
        </div>
    </body>
    </html>
    """

    html_file_path = os.path.join(RESULT_FOLDER, 'analyse_trames.html')
    with open(html_file_path, 'w', encoding='utf-8') as html_file:
        html_file.write(html_content)
    print(f"Fichier HTML généré avec succès : {html_file_path}")

# Système interactif pour demander à l'utilisateur le fichier à analyser
print("Liste des fichiers disponibles dans le dossier courant :")
files = [f for f in os.listdir('.') if os.path.isfile(f)]
for i, file in enumerate(files):
    print(f"{i + 1}. {file}")

file_choice = int(input("Veuillez choisir un fichier à analyser (numéro) : "))
input_file = files[file_choice - 1]
csv_file = 'trame.csv'

# Traiter le fichier et générer les résultats
vulnerabilities = process_file(input_file, os.path.join(RESULT_FOLDER, csv_file))

# Générer le fichier HTML avec les résultats
generate_html(input_file, csv_file, vulnerabilities)