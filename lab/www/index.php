<?php
/* Deliberately trivial: the php2shell bugs are in the engine, not the app.
 * If this page ran, the request survived parsing and RINIT. */
header('Content-Type: text/plain');
echo "hello from PHP " . PHP_VERSION . "\n";
echo "request reached application code\n";
