import csv
import re
from datetime import datetime

def convert_to_unix_timestamp(time_str):
    # Convertir l'horodatage en secondes Unix à partir de "HH:MM:SS.ssssss"
    try:
        time_format = "%H:%M:%S.%f"
        current_time = datetime.strptime(time_str, time_format)
        epoch_time = datetime(1970, 1, 1)
        delta = current_time - epoch_time
        return delta.total_seconds()
    except ValueError:
        # Si le format ne correspond pas, retourner None
        return None

def parse_line(line):
    # Utiliser des expressions régulières pour extraire les informations nécessaires
    pattern = r"(\d{2}:\d{2}:\d{2}\.\d{6})\s+IP\s+([a-zA-Z0-9.-]+)(?:\.(\d+))?\s+>\s+([a-zA-Z0-9.-]+)(?:\.(\d+))?:"
    match = re.search(pattern, line)
    
    if match:
        timestamp = match.group(1)
        source_ip = match.group(2)
        dest_ip = match.group(4)
        
        # Convertir l'horodatage en Unix
        unix_timestamp = convert_to_unix_timestamp(timestamp)
        
        if unix_timestamp is not None:
            return unix_timestamp, source_ip, dest_ip
    return None

def pad_to_length(value, length=50):
    # Ajouter des espaces pour que la chaîne ait une longueur d'au moins 'length'
    return str(value).ljust(length)

def replace_ssh_with_22(ip_address):
    # Remplacer toutes les occurrences de '.ssh' par '.22' dans l'adresse IP
    return ip_address.replace('.ssh', '.22')

def replace_http_with_80(ip_address):
    # Remplacer toutes les occurrences de '.http' par '.80' dans l'adresse IP
    return ip_address.replace('.http', '.80')

def process_file(input_file, output_file):
    # Lire le fichier d'entrée et extraire les données
    with open(input_file, 'r') as infile, open(output_file, 'w', newline='', encoding='utf-8') as outfile:
        csv_writer = csv.writer(outfile, delimiter=';')  # Utilisation du point-virgule comme séparateur
        csv_writer.writerow(['Horodatage Unix', 'IP Source', 'IP Destination'])  # En-têtes de colonnes modifiées

        for line in infile:
            result = parse_line(line)
            if result:
                # Appliquer un "padding" de 50 caractères pour toutes les colonnes
                # Remplacer ".ssh" par ".22" et ".http" par ".80" dans les adresses IP source et destination
                source_ip = replace_http_with_80(replace_ssh_with_22(result[1]))
                dest_ip = replace_http_with_80(replace_ssh_with_22(result[2]))
                
                # Construire la ligne avec le padding et les adresses IP modifiées
                padded_result = [
                    pad_to_length(result[0], 50),  # Horodatage Unix
                    pad_to_length(source_ip, 50),  # IP Source avec remplacement
                    pad_to_length(dest_ip, 50)     # IP Destination avec remplacement
                ]
                csv_writer.writerow(padded_result)

# Spécifiez les fichiers d'entrée et de sortie
input_file = 'trame.txt'  # Remplacez par le chemin réel de votre fichier
output_file = 'trame.csv'  # Le fichier CSV de sortie

# Traitez le fichier
process_file(input_file, output_file)
