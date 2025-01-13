import os
import csv
import re
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

# Fonction pour traiter le fichier et générer un fichier CSV avec les données
def process_file(input_file_path, output_file_path):
    source_ips = []
    dest_ips = []

    with open(input_file_path, 'r', encoding='utf-8') as infile, open(output_file_path, 'w', newline='', encoding='utf-8') as outfile:
        csv_writer = csv.writer(outfile, delimiter=';')  # Utilisation du point-virgule comme séparateur
        csv_writer.writerow(['Horodatage Unix', 'IP Source', 'IP Destination'])  # En-têtes de colonnes

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

    # Créer les graphiques après avoir traité les lignes
    create_graphs(source_ips, dest_ips)

# Fonction pour créer les graphiques
def create_graphs(source_ips, dest_ips):
    source_ip_counts = Counter(source_ips)
    dest_ip_counts = Counter(dest_ips)

    # Graphique des IP source
    plt.figure(figsize=(12, 8))
    plt.bar(source_ip_counts.keys(), source_ip_counts.values(), color='blue')
    plt.xlabel('IP Source')
    plt.ylabel('Occurrences')
    plt.title('Occurrences des IP Source')
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.savefig(os.path.join(RESULT_FOLDER, 'source_ip_occurrences.png'))
    plt.clf()

    # Graphique des IP destination
    plt.figure(figsize=(12, 8))
    plt.bar(dest_ip_counts.keys(), dest_ip_counts.values(), color='red')
    plt.xlabel('IP Destination')
    plt.ylabel('Occurrences')
    plt.title('Occurrences des IP Destination')
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.savefig(os.path.join(RESULT_FOLDER, 'destination_ip_occurrences.png'))
    plt.clf()

# Fonction pour générer le fichier Markdown avec les résultats
def generate_markdown(input_file, csv_file):
    markdown_content = f"# Analyse de Trames\n\n"
    markdown_content += f"Le fichier `{input_file}` a été analysé avec succès.\n\n"

    # Ajouter le lien vers le fichier CSV
    markdown_content += f"## Téléchargement des résultats\n\n"
    markdown_content += f"Vous pouvez télécharger le fichier CSV contenant les données extraites [ici](./results/{csv_file}).\n\n"

    # Ajouter les graphiques
    markdown_content += f"### Graphique des IP Source\n\n"
    markdown_content += f"![Source IP Occurrences](./results/source_ip_occurrences.png)\n\n"

    markdown_content += f"### Graphique des IP Destination\n\n"
    markdown_content += f"![Destination IP Occurrences](./results/destination_ip_occurrences.png)\n\n"

    # Sauvegarder le fichier markdown
    md_file_path = os.path.join(RESULT_FOLDER, 'analyse_trames.md')
    with open(md_file_path, 'w', encoding='utf-8') as md_file:
        md_file.write(markdown_content)
    print(f"Fichier Markdown généré avec succès : {md_file_path}")

# Spécifier le fichier d'entrée
input_file = 'fichier1000.txt'  # Remplacer par le chemin réel de votre fichier
csv_file = 'trame.csv'  # Nom du fichier CSV de sortie

# Traiter le fichier et générer les résultats
process_file(input_file, os.path.join(RESULT_FOLDER, csv_file))

# Générer le fichier Markdown avec les résultats
generate_markdown(input_file, csv_file)
