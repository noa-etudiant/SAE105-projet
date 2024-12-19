def extraire_evenements_txt(fichier_txt):
    evenements = []
    
    try:
        with open(fichier_txt, 'r', encoding='utf-8') as f:
            contenu = f.read()
            evenements_bruts = contenu.split('BEGIN:VEVENT')[1:]
            
            for evenement_brut in evenements_bruts:
                evenement = {}
                
                if 'SUMMARY:' in evenement_brut:
                    evenement['Horodatage Unix'] = evenement_brut.split('SUMMARY:')[1].split('\n')[0].strip()
                else:
                    evenement['THorodatage Unix'] = "vide"
                
                if 'DTSTART:' in evenement_brut:
                    evenement['Date_debut'] = evenement_brut.split('DTSTART:')[1].split('\n')[0].strip()
                else:
                    evenement['Date_debut'] = "vide"
                
                if 'DTEND:' in evenement_brut:
                    evenement['Date_fin'] = evenement_brut.split('DTEND:')[1].split('\n')[0].strip()
                else:
                    evenement['Date_fin'] = "vide"
                
                if 'LOCATION:' in evenement_brut:
                    lieux = evenement_brut.split('LOCATION:')[1].split('\n')[0].strip()
                    evenement['Lieu'] = lieux if lieux else "vide"
                else:
                    evenement['Lieu'] = "vide"
                
                if 'DESCRIPTION:' in evenement_brut:
                    description = evenement_brut.split('DESCRIPTION:')[1].split('\n')[0].strip()
                    evenement['Description'] = description if description else "vide"
                else:
                    evenement['Description'] = "vide"

                evenements.append(evenement)
    
    except FileNotFoundError:
        print(f"Le fichier {fichier_txt} n'a pas été trouvé.")
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier TXT : {e}")
    
    return evenements

def generer_csv(fichier_csv, evenements):
    entetes = [u'Horodatage Unix', u'protocole (IP)', u'IP source et Port', u'IP destination et Port', u'Indicateurs TCP', u'Numéro de séquence', u'Numéro d acquittement', u'taille de la fenêtre', u'Longueur de la charge utile']
    
    with open(fichier_csv, 'w', encoding='utf-8') as f:
        ligneEntete = ";".join(entetes) + "\n"
        f.write(ligneEntete)
        
        for evenement in evenements:
            ligne = f"{evenement.get('Titre', 'vide')};{evenement.get('Date_debut', 'vide')};{evenement.get('Date_fin', 'vide')};{evenement.get('Lieu', 'vide')};{evenement.get('Description', 'vide')}\n"
            f.write(ligne)

def main():
    fichier_txt = 'fichier1000.txt'
    fichier_csv = 'rapport.csv'
    
    evenements = extraire_evenements_txt(fichier_txt)
    generer_csv(fichier_csv, evenements)
    print(f"Le fichier CSV '{fichier_csv}' a été créé avec succès.")

if __name__ == "__main__":
    main()
