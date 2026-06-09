# Script légitime - Serveur HTTP simple
# Ce fichier ne devrait PAS déclencher d'alerte YARA

from http.server import HTTPServer, SimpleHTTPRequestHandler
import json

class MonHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            reponse = json.dumps({"status": "ok", "version": "1.0"})
            self.wfile.write(reponse.encode())
        else:
            super().do_GET()

if __name__ == "__main__":
    serveur = HTTPServer(("localhost", 8080), MonHandler)
    print("Serveur démarré sur http://localhost:8080")
    serveur.serve_forever()
