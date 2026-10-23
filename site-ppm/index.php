<?php
header("Content-Type: text/plain");
echo "PHP_REACHED script=" . basename(__FILE__) . " uri=" . $_SERVER["REQUEST_URI"] . " method=" . $_SERVER["REQUEST_METHOD"] . " files=" . count($_FILES) . " post=" . count($_POST) . " mpg=" . ($_SERVER["MPG"] ?? "-") . " sapi=" . PHP_SAPI . " php=" . PHP_VERSION . "\n";
