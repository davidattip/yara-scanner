// Script legitime - Petit client d'API REST en Node.js
// Ce fichier ne devrait PAS declencher d'alerte YARA.
// Recuperation et affichage de donnees publiques via fetch.

const API_URL = "https://api.exemple.fr/v1";

async function recupererUtilisateurs() {
    const reponse = await fetch(`${API_URL}/users`);
    if (!reponse.ok) {
        throw new Error(`Erreur HTTP : ${reponse.status}`);
    }
    return reponse.json();
}

function formaterUtilisateur(user) {
    return `${user.nom} <${user.email}>`;
}

async function main() {
    try {
        const utilisateurs = await recupererUtilisateurs();
        console.log(`Nombre d'utilisateurs : ${utilisateurs.length}`);
        utilisateurs.forEach((u) => console.log(formaterUtilisateur(u)));
    } catch (err) {
        console.error("Impossible de recuperer les utilisateurs :", err.message);
    }
}

main();
