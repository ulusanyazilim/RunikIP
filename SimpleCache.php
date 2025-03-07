<?php
namespace Security;

class SimpleCache {
    private $cacheDir;
    
    public function __construct(string $cacheDir) {
        $this->cacheDir = rtrim($cacheDir, '/') . '/';
        
        if (!is_dir($this->cacheDir)) {
            mkdir($this->cacheDir, 0755, true);
        }
    }
    
    public function set(string $key, $value, int $ttl = 3600): bool {
        $filename = $this->getFilename($key);
        $data = [
            'expires' => time() + $ttl,
            'value' => $value
        ];
        
        return file_put_contents($filename, serialize($data)) !== false;
    }
    
    public function get(string $key) {
        $filename = $this->getFilename($key);
        
        if (!file_exists($filename)) {
            return null;
        }
        
        $data = unserialize(file_get_contents($filename));
        
        if ($data === false) {
            return null;
        }
        
        if (time() > $data['expires']) {
            unlink($filename);
            return null;
        }
        
        return $data['value'];
    }
    
    public function has(string $key): bool {
        $filename = $this->getFilename($key);
        
        if (!file_exists($filename)) {
            return false;
        }
        
        $data = unserialize(file_get_contents($filename));
        
        if ($data === false) {
            return false;
        }
        
        if (time() > $data['expires']) {
            unlink($filename);
            return false;
        }
        
        return true;
    }
    
    public function delete(string $key): bool {
        $filename = $this->getFilename($key);
        
        if (file_exists($filename)) {
            return unlink($filename);
        }
        
        return true;
    }
    
    public function clear(): bool {
        $files = glob($this->cacheDir . '*');
        
        foreach ($files as $file) {
            if (is_file($file)) {
                unlink($file);
            }
        }
        
        return true;
    }
    
    private function getFilename(string $key): string {
        return $this->cacheDir . md5($key) . '.cache';
    }
} 