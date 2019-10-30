import configparser
import importlib

if __name__ == "__main__":
    import ghia
    importlib.reload(ghia)  # force reload (config could change)
    ghia.create_app(None)
