<?php
namespace Security;

class SimpleCache {
    private $cachePath;
    private $defaultDuration = 3600; // 1 saat

    public function __construct(string $cachePath = 'cache/') {
        $this->cachePath = rtrim($cachePath, '/') . '/';
        if (!is_dir($this->cachePath)) {
            mkdir($this->cachePath, 0755, true);
        }
    }

    public function get(string $key) {
        $filename = $this->getCacheFilename($key);
        
        if (!file_exists($filename)) {
            return null;
        }

        $content = file_get_contents($filename);
        $data = json_decode($content, true);

        if (!$data || (isset($data['expires']) && $data['expires'] < time())) {
            @unlink($filename);
            return null;
        }

        return $data['value'];
    }

    public function set(string $key, $value, int $duration = null): bool {
        $filename = $this->getCacheFilename($key);
        $duration = $duration ?? $this->defaultDuration;

        $data = [
            'expires' => time() + $duration,
            'value' => $value
        ];

        return file_put_contents($filename, json_encode($data)) !== false;
    }

    public function delete(string $key): bool {
        $filename = $this->getCacheFilename($key);
        if (file_exists($filename)) {
            return @unlink($filename);
        }
        return true;
    }

    private function getCacheFilename(string $key): string {
        return $this->cachePath . md5($key) . '.cache';
    }
} 