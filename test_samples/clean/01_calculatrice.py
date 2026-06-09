# Script légitime - Calculatrice simple
# Ce fichier ne devrait PAS déclencher d'alerte YARA

def addition(a, b):
    return a + b

def soustraction(a, b):
    return a - b

def multiplication(a, b):
    return a * b

def division(a, b):
    if b == 0:
        raise ValueError("Division par zéro impossible")
    return a / b

if __name__ == "__main__":
    print("Résultat :", addition(5, 3))
    print("Résultat :", multiplication(4, 7))
