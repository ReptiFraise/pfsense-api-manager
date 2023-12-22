from livereload import Server, shell

commande_compilation = "sphinx-build -b html source/ build/"

if __name__ == '__main__':
    # Instanciation du serveur
    server = Server()
    # Ajoute des observers sur les fichiers de documentation
    # (modifications scrutées toutes les 1s)
    # et exécute, si modification, la commande de compilation
    server.watch('source/*.rst', shell(commande_compilation), delay=1)
    server.watch('source/*.py', shell(commande_compilation), delay=1)
    server.watch('source/_static/*', shell(commande_compilation), delay=1)
    server.watch('source/_templates/*', shell(commande_compilation), delay=1)
    # Lance le serveur
    server.serve(root='build', port=8080, host='127.0.0.1')