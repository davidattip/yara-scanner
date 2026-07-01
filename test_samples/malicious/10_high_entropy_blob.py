# FICHIER DE TEST - Payload masque en base64 URL-safe
# Objectif pedagogique : demontrer la DETECTION PAR ENTROPIE.
#
# La regle YARA Base64_Encoded_Payload cherche [A-Za-z0-9+/]{100,}.
# Ici le blob utilise l alphabet URL-safe (- et _), qui fragmente les
# runs sous 100 caracteres : YARA ne detecte RIEN. Mais l entropie du
# blob reste elevee, donc l analyse statistique le repere.

CONFIG_TOKEN = "7Pq--ZJAA6XXVWKVH78vujRB_sv18DRnxYEsIeDfw4DUhoJ0-ICBr92kbZ979oMF68blo3kITjGfVPR8O9PVjlLGWUg3LR3i-SAmTkCPb2Z1ms7waFsHbcWCXfyKWMdtlzdQ_xn9ieJzkZNDmPuNy5YzKth-3ALX-Ny0ncPcKIUx_XV0_xWExiYS83DSa8Rh6jONbgSVFvZFryVYSrJvTKvXU45mMPCMlAOF5x9lGG4tZ32cmXmoxLYIps72Azp20UibH1u5G_TRElmLj2CPMiwZArkJavDAwhPskihrWscq0R-bvsl2No9OV7L77oeC"

def charger_configuration(token: str) -> int:
    return len(token.encode())

if __name__ == "__main__":
    print("Configuration chargee :", charger_configuration(CONFIG_TOKEN), "octets")
