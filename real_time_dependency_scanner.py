import hashlib
import threading
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import json
import os

class DependencyModificationHandler(FileSystemEventHandler):
    def __init__(self, scanner):
        self.scanner = scanner
        super().__init__()
    
    def on_modified(self, event):
        if not event.is_directory:
            self.scanner.check_modification(event.src_path)
    
    def on_created(self, event):
        if not event.is_directory:
            self.scanner.check_new_file(event.src_path)

class RealTimeDependencyScanner:
    def __init__(self, sbom_path="sbom.json", blocklist_path="security/blocklist.json"):
        # Configuração de logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Carregar SBOM e blocklist
        self.sbom = self.load_sbom(sbom_path)
        self.blocklist = self.load_blocklist(blocklist_path)
        
        # Inicializar watchdog
        self.observer = Observer()
        self.event_handler = DependencyModificationHandler(self)
        
        # Configuração de verificação periódica
        self.check_interval = 3600  # 1 hora
        self.last_full_check = 0
    
    def load_sbom(self, path):
        try:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    return json.load(f)
            else:
                self.logger.warning(f"SBOM file not found at {path}, creating new one")
                return {}
        except Exception as e:
            self.logger.error(f"Failed to load SBOM: {str(e)}")
            return {}
    
    def load_blocklist(self, path):
        try:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    return json.load(f)
            else:
                self.logger.warning(f"Blocklist not found at {path}")
                return {"packages": [], "hashes": [], "patterns": []}
        except Exception as e:
            self.logger.error(f"Failed to load blocklist: {str(e)}")
            return {"packages": [], "hashes": [], "patterns": []}
    
    def calculate_hash(self, filepath):
        try:
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for block in iter(lambda: f.read(4096), b''):
                    sha256.update(block)
            return sha256.hexdigest()
        except Exception as e:
            self.logger.error(f"Failed to calculate hash for {filepath}: {str(e)}")
            return None
    
    def monitor_filesystem(self, paths_to_watch):
        for path in paths_to_watch:
            if os.path.exists(path):
                self.observer.schedule(self.event_handler, path, recursive=True)
                self.logger.info(f"Monitoring {path} for changes")
            else:
                self.logger.warning(f"Path {path} does not exist, skipping")
        
        self.observer.start()
        self.logger.info("File system monitoring started")
        
        try:
            while True:
                # Verificação periódica completa
                current_time = time.time()
                if current_time - self.last_full_check > self.check_interval:
                    self.perform_full_check()
                    self.last_full_check = current_time
                
                time.sleep(10)
        except KeyboardInterrupt:
            self.observer.stop()
        self.observer.join()
    
    def perform_full_check(self):
        self.logger.info("Performing full dependency check")
        for filepath, stored_hash in self.sbom.items():
            if os.path.exists(filepath):
                current_hash = self.calculate_hash(filepath)
                if current_hash != stored_hash:
                    self.respond_to_tampering(filepath, stored_hash, current_hash)
            else:
                self.logger.warning(f"File {filepath} in SBOM no longer exists")
    
    def check_modification(self, filepath):
        if filepath in self.sbom:
            current_hash = self.calculate_hash(filepath)
            if current_hash and current_hash != self.sbom[filepath]:
                self.respond_to_tampering(filepath, self.sbom[filepath], current_hash)
        else:
            self.check_new_file(filepath)
    
    def check_new_file(self, filepath):
        # Verificar se o novo arquivo está na blocklist
        filename = os.path.basename(filepath)
        file_hash = self.calculate_hash(filepath)
        
        if any(pattern in filename for pattern in self.blocklist["patterns"]) or \
           file_hash in self.blocklist["hashes"]:
            self.logger.critical(f"Blocklisted file detected: {filepath}")
            self.respond_to_tampering(filepath, None, file_hash, is_blocklisted=True)
        else:
            # Adicionar ao SBOM
            self.sbom[filepath] = file_hash
            self.save_sbom()
            self.logger.info(f"New file added to SBOM: {filepath}")
    
    def save_sbom(self):
        try:
            with open("sbom.json", 'w') as f:
                json.dump(self.sbom, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save SBOM: {str(e)}")
    
    def respond_to_tampering(self, filepath, old_hash=None, new_hash=None, is_blocklisted=False):
        self.logger.critical(f"Tampering detected in {filepath}")
        self.logger.info(f"Old hash: {old_hash}, New hash: {new_hash}")
        
        # Implementar medidas de resposta
        threading.Thread(target=self.isolate_system).start()
        threading.Thread(target=self.alert_security_team, 
                        args=(filepath, old_hash, new_hash, is_blocklisted)).start()
        
        if old_hash and not is_blocklisted:
            threading.Thread(target=self.rollback_changes, args=(filepath,)).start()
    
    def isolate_system(self):
        self.logger.info("Isolating system to prevent further damage")
        # Implementação real isolaria o sistema da rede
    
    def alert_security_team(self, filepath, old_hash, new_hash, is_blocklisted):
        self.logger.info("Alerting security team")
        # Implementação real enviaria alertas via email, SMS, etc.
    
    def rollback_changes(self, filepath):
        self.logger.info(f"Rolling back changes to {filepath}")
        # Implementação real restauraria de backup ou sistema de controle de versão

if __name__ == "__main__":
    scanner = RealTimeDependencyScanner()
    scanner.monitor_filesystem(["/app/lib", "/app/dependencies"])