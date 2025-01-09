import re

def extraire_evenements_txt(fichier_txt):
    evenements = []
    
    # Expressions régulières simplifiées pour tester
    regex_heure = r"(?P<horodatage>\d{2}:\d{2}:\d{2}\.\d{6})"  # Récupère l'horodatage
    regex_tcp = r"(?P<horodatage>\d{2}:\d{2}:\d{2}\.\d{6})\s+IP\s+(?P<ip_source>[\w\.-]+)\.(?P<port_source>\d+)\s+>\s+(?P<ip_dest>[\d\w\.-]+)\.(?P<port_dest>\d+):\s+Flags\s+\[.*\],\s+seq\s+\d+:\d+,\s+ack\s+\d+,\s+win\s+\d+,\s+options\s+\[.*\],\s+length\s+\d+"
    regex_dns_query = r"(?P<horodatage>\d{2}:\d{2}:\d{2}\.\d{6})\s+IP\s+(?P<ip_source>[\w\.-]+)\.(?P<port_source>\d+)\s+>\s+(?P<ip_dest>[\d\.]+)\.(?P<port_dest>\d+):\s+(?P<length>\d+)\+?\s(?P<type>PTR\?|A\?)\s(?P<domain>[\w\.-]+)"
    
    try:
        with open(fichier_txt, 'r', encoding='utf-8') as f:
            contenu = f.readlines()

            # Vérification de la lecture du fichier
            if not contenu:
                print(f"Le fichier {fichier_txt} est vide.")
                return evenements

            # Affichage des 5 premières lignes du fichier pour vérifier la lecture
            print("Aperçu des 5 premières lignes du fichier :")
            for i in range(min(5, len(contenu))):
                print(contenu[i])

            # Traitement des lignes
            for ligne in contenu:
                ligne = ligne.strip()  # Supprimer les espaces en trop
                print(f"Traitement de la ligne: '{ligne}'")  # Affichage de la ligne traitée

                # Première étape : Essayer de capturer uniquement l'horodatage
                match_heure = re.match(regex_heure, ligne)
                if match_heure:
                    print(f"Horodatage trouvé: {match_heure.group('horodatage')}")
                
                # Deuxième étape : Essayer de capturer un paquet TCP complet
                match_tcp = re.match(regex_tcp, ligne)
                if match_tcp:
                    print(f"Match trouvé avec la regex TCP: {ligne}")
                    evenement = match_tcp.groupdict()
                    evenements.append(evenement)

                # Troisième étape : Essayer de capturer une requête DNS
                match_dns = re.match(regex_dns_query, ligne)
                if match_dns:
                    print(f"Match trouvé avec la regex DNS: {ligne}")
                    evenement = match_dns.groupdict()
                    evenements.append(evenement)

    except FileNotFoundError:
        print(f"Le fichier {fichier_txt} n'a pas été trouvé.")
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier TXT : {e}")
    
    return evenements


def main():
    fichier_txt = 'fichier1000.txt'  # Le nom du fichier texte avec les paquets réseau
    evenements = extraire_evenements_txt(fichier_txt)
    if evenements:
        print(f"Nombre d'événements extraits: {len(evenements)}")
        for evenement in evenements:
            print(evenement)
    else:
        print("Aucun événement trouvé dans le fichier TXT.")


if __name__ == "__main__":
    main()

