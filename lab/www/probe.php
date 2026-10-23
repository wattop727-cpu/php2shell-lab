<?php
header('Content-Type: application/json');
echo json_encode([
    'version' => PHP_VERSION,
    'patched_8_5_12' => version_compare(PHP_VERSION, '8.5.12', '>='),
    'upload_progress' => ini_get('session.upload_progress.enabled'),
    'memory_limit' => ini_get('memory_limit'),
]);
