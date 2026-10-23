<?php
// Client HTTP brut : envoie des en-têtes exactement tels que fournis
// (doublons, casse, espaces, obs-fold), ce que curl ne permet pas.
//
// Usage : php raw.php METHOD PATH BODYFILE|- [--no-cl] "Header: valeur" ...
//   Les séquences \t \r \n des en-têtes sont interprétées.
//   Content-Length est ajouté automatiquement sauf avec --no-cl.
// Sortie : première ligne = code HTTP, puis le corps de la réponse.

[$self, $method, $path, $bodyFile] = array_slice($argv, 0, 4) + [null, null, null, '-'];
$args = array_slice($argv, 4);
$noCl = in_array('--no-cl', $args, true);
$headers = array_values(array_filter($args, fn($a) => $a !== '--no-cl'));

$body = ($bodyFile === '-' || $bodyFile === null) ? '' : file_get_contents($bodyFile);

$req = "$method $path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n";
foreach ($headers as $h) {
    $req .= stripcslashes($h) . "\r\n";
}
if (!$noCl) {
    $req .= 'Content-Length: ' . strlen($body) . "\r\n";
}
$req .= "\r\n" . $body;

$fp = fsockopen('127.0.0.1', 80, $errno, $errstr, 5);
if (!$fp) {
    fwrite(STDERR, "connexion impossible : $errstr\n");
    exit(1);
}
stream_set_timeout($fp, 10);
fwrite($fp, $req);
$resp = stream_get_contents($fp);
fclose($fp);

[$head, $respBody] = explode("\r\n\r\n", $resp, 2) + [1 => ''];
preg_match('#^HTTP/\S+ (\d{3})#', $head, $m);
echo ($m[1] ?? '000') . "\n";
if (stripos($head, "transfer-encoding: chunked") !== false) {
    // Décodage minimal du chunked pour lire le corps
    $out = '';
    while (preg_match('/^([0-9a-f]+)\r\n/i', $respBody, $c) && hexdec($c[1]) > 0) {
        $len = hexdec($c[1]);
        $out .= substr($respBody, strlen($c[0]), $len);
        $respBody = substr($respBody, strlen($c[0]) + $len + 2);
    }
    $respBody = $out;
}
echo $respBody;
