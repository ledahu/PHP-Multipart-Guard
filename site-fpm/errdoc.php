<?php
header("Content-Type: text/plain");
echo "ERRDOC_REACHED method=" . $_SERVER["REQUEST_METHOD"] . " files=" . count($_FILES) . "\n";
