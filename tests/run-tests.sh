#!/usr/bin/env bash
# Tests automatisés de Multipart Guard sur WAMP (mod_php).
#
# Usage : tests/run-tests.sh [multipart-guard|multipart-guard-doc|rewrite] [site|site-fcgi|site-fpm|site-ppm]
#         (défaut : multipart-guard site)
#
# Installe la variante choisie dans site/.htaccess (guard + règles de l'app),
# puis vérifie pour chaque requête :
#   - le code HTTP ;
#   - si un script PHP a été exécuté (marqueur PHP_REACHED) ;
#   - si le PARSEUR multipart de PHP a tourné. Le corps "canary.bin" contient
#     21 fichiers pour max_file_uploads=20 : PHP écrit alors un avertissement
#     dans php_error.log pendant l'analyse, avant tout script. Pas
#     d'avertissement = le parseur n'a jamais vu la requête.

set -u
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")"

VARIANT=${1:-multipart-guard}
SITE=${2:-site}
ROOT=..
PHP=/c/wamp64/bin/php/php8.4.25/php.exe
PHPLOG=/c/wamp64/logs/php_error.log
BASE=http://localhost/multipart2hell/$SITE
S=/multipart2hell/$SITE
CT='Content-Type: multipart/form-data; boundary=XyZ'
# Valeur attendue sur le banc WAMP (8M), pour contrôler les corps tronqués.
POST_MAX_BYTES=8388608

# Un journal absent ou illisible ne permet pas de prouver un refus avant PHP.
[ -f "$PHPLOG" ] && [ -r "$PHPLOG" ] || {
    echo "ERREUR : journal PHP absent ou illisible : $PHPLOG"; exit 1
}

# Les deux éditions du guard doivent contenir exactement les mêmes directives
directives() { grep -vE '^\s*#|^\s*$' "$1"; }
if ! diff <(directives "$ROOT/guard/multipart-guard.htaccess") <(directives "$ROOT/guard/multipart-guard-doc.htaccess") >/dev/null; then
    echo "ERREUR : multipart-guard.htaccess et multipart-guard-doc.htaccess diffèrent"; exit 1
fi

# Guard prêt pour le site de test : les fichiers distribués ne contiennent
# aucune URL autorisée, on insère celles du site juste avant le moteur
# (première ligne contenant "ENGINE"). L'édition rewrite a ses propres URL.
guard_for_site() {
    if grep -q MPG_ALLOWED "$ROOT/guard/$VARIANT.htaccess"; then
        awk -v s="$S" '!done && /ENGINE/ {
            print "SetEnvIfExpr \"%{REQUEST_URI} == '\''" s "/upload.php'\''\"  MPG_ALLOWED=1"
            print "SetEnvIfExpr \"%{REQUEST_URI} == '\''" s "/api/upload'\''\"  MPG_ALLOWED=1"
            print ""; done = 1 }
            { print }' "$ROOT/guard/$VARIANT.htaccess"
    else
        sed "s#/multipart2hell/site/#$S/#g" "$ROOT/guard/$VARIANT.htaccess"
    fi
}

# .htaccess = guard (avec les URL de test) + handler PHP éventuel + app
{
    guard_for_site
    [ -f "$ROOT/$SITE/handler.rules" ] && cat "$ROOT/$SITE/handler.rules"
    sed "s#/multipart2hell/site/#$S/#g" "$ROOT/$SITE/app.rules"
} > "$ROOT/$SITE/.htaccess" || exit 1
[ -f canary.bin ] || { echo "canary.bin manquant"; exit 1; }
[ -f big.bin ] || head -c 11000000 /dev/zero > big.bin
# Corps urlencoded : 9 Mo (> post_max_size 8M) et 8 Mo (< 8M)
[ -f big9.txt ] || head -c 9000000 /dev/zero | tr '\0' 'a' | sed 's/^/x=/' > big9.txt
[ -f big8.txt ] || head -c 8000000 big9.txt > big8.txt

pass=0; fail=0; failed=()

# Avertissements PHP émis AVANT tout script : parseur multipart
# (max_file_uploads dépassé) ou dépassement de post_max_size.
parser_count() {
    local count rc
    count=$(grep -cE "allowable file uploads|exceeds the limit|Actual POST length" "$PHPLOG" 2>/dev/null)
    rc=$?
    [ "$rc" -le 1 ] || return 1
    printf '%s\n' "$count"
}

canary_count() {
    local count rc
    count=$(grep -c 'allowable file uploads' "$PHPLOG" 2>/dev/null)
    rc=$?
    [ "$rc" -le 1 ] || return 1
    printf '%s\n' "$count"
}

# check ID EXPECT DESCRIPTION -- commande...
#   EXPECT : DENY        403 ou 413, aucun PHP exécuté, aucun avertissement PHP
#            LIMIT:script aucun avertissement PHP ; 413 sans script, ou 200/413
#                        du script attendu avec body_bytes <= post_max_size
#            CANARY:script 200 du script attendu ET avertissement multipart
#            PASS:script 200 et c'est ce script qui a été exécuté
#            SAFE:script refus, ou exécution de ce script précis seulement
check() {
    local id=$1 expect=$2 desc=$3; shift 4
    local before after canary_before canary_after out code script bytes parsed verdict ok=0
    before=$(parser_count) && canary_before=$(canary_count) || {
        echo "ERREUR : lecture du journal PHP impossible avant $id"; exit 1
    }
    out=$("$@" 2>/dev/null)
    after=$(parser_count) && canary_after=$(canary_count) || {
        echo "ERREUR : lecture du journal PHP impossible après $id"; exit 1
    }
    if [ "$after" -lt "$before" ] || [ "$canary_after" -lt "$canary_before" ]; then
        echo "ERREUR : journal PHP tronqué pendant $id"; exit 1
    fi
    code=$(printf '%s\n' "$out" | head -1)
    script=$(printf '%s' "$out" | grep -o 'PHP_REACHED script=[^ ]*' | head -1 | cut -d= -f2)
    printf '%s' "$out" | grep -q ERRDOC_REACHED && script="errdoc.php"
    bytes=$(printf '%s' "$out" | grep -o 'body_bytes=[0-9]*' | head -1 | cut -d= -f2)
    parsed=non; [ "$after" -gt "$before" ] && parsed=OUI

    case $expect in
        DENY)   { [ "$code" = 403 ] || [ "$code" = 413 ]; } && [ -z "$script" ] && [ $parsed = non ] && ok=1 ;;
        LIMIT:*)
            if [ "$parsed" = non ]; then
                if [ "$code" = 413 ] && [ -z "$script" ]; then
                    ok=1
                elif { [ "$code" = 200 ] || [ "$code" = 413 ]; } &&
                     [ "$script" = "${expect#LIMIT:}" ] &&
                     [[ "$bytes" =~ ^[0-9]{1,9}$ ]] && [ "$bytes" -le "$POST_MAX_BYTES" ]; then
                    ok=1
                fi
            fi ;;
        CANARY:*) [ "$code" = 200 ] && [ "$script" = "${expect#CANARY:}" ] &&
                  [ "$canary_after" -gt "$canary_before" ] && ok=1 ;;
        PASS:*) [ "$code" = 200 ] && [ "$script" = "${expect#PASS:}" ] && ok=1 ;;
        SAFE:*) { [[ "$code" =~ ^[345][0-9]{2}$ ]] && [ -z "$script" ] && [ $parsed = non ]; } ||
                { [ "$code" = 200 ] && [ "$script" = "${expect#SAFE:}" ]; } && ok=1 ;;
    esac
    if [ $ok = 1 ]; then verdict=OK; pass=$((pass+1)); else verdict=ECHEC; fail=$((fail+1)); failed+=("$id"); fi
    printf '%-5s %-6s %-4s php=%-12s parseur=%-4s %-16s %s\n' "$id" "$verdict" "$code" "${script:--}" "$parsed" "$expect" "$desc"
}

# Requête via curl ; première ligne de sortie = code HTTP, puis le corps.
c() { local o; o=$(curl -s -w '\n%{http_code}' "$@"); printf '%s\n%s' "$(printf '%s' "$o" | tail -1)" "$(printf '%s' "$o" | sed '$d')"; }
# Requête brute : r METHOD PATH BODY [en-têtes...]
r() { "$PHP" raw.php "$@"; }

echo "=== Multipart Guard — variante : $VARIANT — site : $SITE ==="
echo "PHP exécuté par : $(curl -s "$BASE/article.php" | grep -o 'sapi=.*')"
echo
echo "--- Trafic normal (non-régression) ---"
check N1 PASS:article.php "GET simple"                          -- c "$BASE/article.php"
check N2 PASS:article.php "GET avec query string"               -- c "$BASE/article.php?a=1&multipart=1"
check N3 PASS:article.php "POST urlencoded"                     -- c -d 'a=1&b=2' "$BASE/article.php"
check N4 PASS:article.php "POST JSON"                           -- c -H 'Content-Type: application/json' -d '{"a":1}' "$BASE/article.php"
check N5 PASS:article.php "POST text/plain"                     -- c -H 'Content-Type: text/plain' -d 'hello' "$BASE/article.php"
check N6 PASS:index.php   "GET URL réécrite (contrôleur frontal)" -- c "$BASE/blog/hello"
check N7 PASS:upload.php  "POST urlencoded sur URL autorisée"   -- c -d 'a=1' "$BASE/upload.php"
check N8 PASS:article.php "PUT JSON"                            -- c -X PUT -H 'Content-Type: application/json' -d '{"a":1}' "$BASE/article.php"
check N9 PASS:article.php "POST urlencoded chunked"             -- c -H 'Transfer-Encoding: chunked' -d 'a=1' "$BASE/article.php"

echo
echo "--- Multipart sur URL non autorisée ---"
check M1  DENY "curl -F (navigateur)"                           -- c -F 'f=@canary.bin' "$BASE/article.php"
check M2  DENY "corps canari, Content-Type standard"            -- r POST $S/article.php canary.bin "$CT"
check M3  DENY "casse inhabituelle"                             -- r POST $S/article.php canary.bin 'Content-Type: MuLtIpArT/FoRm-DaTa; boundary=XyZ'
check M4  DENY "multipart/form-data,x (accepté par PHP)"        -- r POST $S/article.php canary.bin 'Content-Type: multipart/form-data,x; boundary=XyZ'
check M5  DENY "multipart/form-data x (accepté par PHP)"        -- r POST $S/article.php canary.bin 'Content-Type: multipart/form-data x; boundary=XyZ'
check M6  DENY "espaces en tête de valeur"                      -- r POST $S/article.php canary.bin 'Content-Type:     multipart/form-data; boundary=XyZ'
check M7  DENY "valeur repliée (obs-fold)"                      -- r POST $S/article.php canary.bin 'Content-Type:\r\n multipart/form-data; boundary=XyZ'
check M8  DENY "Content-Type double : multipart puis text"      -- r POST $S/article.php canary.bin "$CT" 'Content-Type: text/plain'
check M9  DENY "Content-Type double : text puis multipart"      -- r POST $S/article.php canary.bin 'Content-Type: text/plain' "$CT"
check M10 DENY "nom d'en-tête en minuscules"                    -- r POST $S/article.php canary.bin 'content-type: multipart/form-data; boundary=XyZ'
check M11 DENY "chunked, sans Content-Length"                   -- c -H 'Transfer-Encoding: chunked' -H "$CT" --data-binary @canary.bin "$BASE/article.php"
check M12 DENY "multipart/mixed"                                -- r POST $S/article.php canary.bin 'Content-Type: multipart/mixed; boundary=XyZ'
check M13 DENY "méthode PUT"                                    -- r PUT $S/article.php canary.bin "$CT"
check M14 DENY "méthode PATCH"                                  -- r PATCH $S/article.php canary.bin "$CT"
check M15 DENY "URL réécrite vers index.php"                    -- r POST $S/blog/hello canary.bin "$CT"
check M16 DENY "répertoire (DirectoryIndex)"                    -- r POST $S/ canary.bin "$CT"
check M17 DENY "sous-dossier avec RewriteEngine On"             -- r POST $S/sub/page.php canary.bin "$CT"
check M18 DENY "sous-dossier, URL réécrite localement"          -- r POST $S/sub/legacy canary.bin "$CT"
check M19 DENY "sous-dossier avec RewriteEngine Off"            -- r POST $S/sub-off/page.php canary.bin "$CT"
check M20 DENY "ErrorDocument 403 vers un script PHP"           -- r POST $S/sub/page.php canary.bin "$CT"

echo
echo "--- Astuces de chemin autour de la liste blanche ---"
check P1  DENY             "PATH_INFO : upload.php/x"           -- r POST $S/upload.php/x canary.bin "$CT"
check P2  DENY             "casse : UPLOAD.PHP"                 -- r POST $S/UPLOAD.PHP canary.bin "$CT"
check P3  SAFE:upload.php  "double slash"                       -- r POST "${S}//upload.php" canary.bin "$CT"
check P4  SAFE:upload.php  "/./"                                -- r POST $S/./upload.php canary.bin "$CT"
check P5  SAFE:upload.php  "point encodé : upload%2ephp"        -- r POST $S/upload%2ephp canary.bin "$CT"
check P6  SAFE:upload.php  "remontée : sub/../upload.php"       -- r POST $S/sub/../upload.php canary.bin "$CT"
check P7  SAFE:upload.php  "remontée encodée : sub/%2e%2e/upload.php" -- r POST $S/sub/%2e%2e/upload.php canary.bin "$CT"
check P8  DENY             "query : article.php?/upload.php"    -- r POST "$S/article.php?/upload.php" canary.bin "$CT"
check P9  DENY             "article.php/upload.php"             -- r POST $S/article.php/upload.php canary.bin "$CT"
check P10 SAFE:upload.php  "MultiViews : /upload sans extension" -- r POST $S/upload canary.bin "$CT"
check P11 DENY             "slash final : api/upload/"          -- r POST $S/api/upload/ canary.bin "$CT"
check P12 DENY             "casse : api/UPLOAD"                 -- r POST $S/api/UPLOAD canary.bin "$CT"
check P13 SAFE:upload.php  "Windows : upload.php::\$DATA"       -- r POST "$S/upload.php::\$DATA" canary.bin "$CT"
check P14 SAFE:upload.php  "Windows : point final upload.php."  -- r POST $S/upload.php. canary.bin "$CT"
check P15 SAFE:upload.php  "octet nul : upload.php%00.txt"      -- r POST $S/upload.php%00.txt canary.bin "$CT"
check P16 DENY             "hôte absolu dans la ligne de requête" -- r POST "http://localhost$S/article.php" canary.bin "$CT"

echo
echo "--- URL autorisée : seule la forme d'un navigateur passe ---"
check A1  PASS:upload.php "curl -F (navigateur)"                -- c -F 'f=@canary.bin' "$BASE/upload.php"
check A2  CANARY:upload.php "corps canari (contrôle positif)"   -- r POST $S/upload.php canary.bin "$CT"
check A3  PASS:index.php  "URL propre autorisée -> index.php"   -- c -F 'f=@canary.bin' "$BASE/api/upload"
check A4  PASS:upload.php "boundary entre guillemets"           -- r POST $S/upload.php canary.bin 'Content-Type: multipart/form-data; boundary="XyZ"'
check A5  PASS:upload.php "sans espace avant boundary"          -- r POST $S/upload.php canary.bin 'Content-Type: multipart/form-data;boundary=XyZ'
check A6  DENY "chunked, sans Content-Length"                   -- c -H 'Transfer-Encoding: chunked' -H "$CT" --data-binary @canary.bin "$BASE/upload.php"
check A7  DENY "méthode PUT"                                    -- r PUT $S/upload.php canary.bin "$CT"
check A8  DENY "multipart/form-data,x"                          -- r POST $S/upload.php canary.bin 'Content-Type: multipart/form-data,x; boundary=XyZ'
check A9  DENY "Content-Type double"                            -- r POST $S/upload.php canary.bin "$CT" 'Content-Type: text/plain'
check A10 DENY "paramètre en plus (charset)"                    -- r POST $S/upload.php canary.bin 'Content-Type: multipart/form-data; charset=utf-8; boundary=XyZ'
check A11 DENY "xboundary piège (PHP prend le mauvais)"         -- r POST $S/upload.php canary.bin 'Content-Type: multipart/form-data; xboundary=AAA; boundary=XyZ'
check A12 DENY "corps > limite"                                  -- c -F 'f=@big.bin' "$BASE/upload.php"
check A13 PASS:upload.php "majuscules (non ambigu)"                -- r POST $S/upload.php canary.bin 'Content-Type: MULTIPART/FORM-DATA; boundary=XyZ'
check A14 DENY "boundary : guillemet fermant absent"            -- r POST $S/upload.php canary.bin 'Content-Type: multipart/form-data; boundary="XyZ'
check A15 DENY "boundary : guillemet ouvrant absent"            -- r POST $S/upload.php canary.bin 'Content-Type: multipart/form-data; boundary=XyZ"'

echo
echo "--- Taille des POST ordinaires (limite = post_max_size 8M) ---"
check S1 DENY             "POST urlencoded 9 Mo"                -- c --data-binary @big9.txt "$BASE/article.php"
check S2 DENY             "POST JSON 9 Mo"                      -- c --data-binary @big9.txt -H 'Content-Type: application/json' "$BASE/article.php"
check S3 LIMIT:article.php "POST urlencoded 9 Mo chunked"       -- c --data-binary @big9.txt -H 'Transfer-Encoding: chunked' "$BASE/article.php"
check S4 PASS:article.php "POST urlencoded 8 Mo (sous la limite)" -- c --data-binary @big8.txt "$BASE/article.php"
check S5 PASS:article.php "POST 8 Mo chunked (sous la limite)"  -- c --data-binary @big8.txt -H 'Transfer-Encoding: chunked' "$BASE/article.php"
check S6 PASS:article.php "PUT JSON 9 Mo (non concerné)"        -- c -X PUT --data-binary @big9.txt -H 'Content-Type: application/json' "$BASE/article.php"

echo
echo "--- Mode OBSERVE (décisions journalisées, limite de corps maintenue) ---"
if [ "$SITE" = site-ppm ]; then
    # Guard dans la configuration serveur (<Location>) : changer de mode
    # demande un redémarrage d'Apache, ce test est donc omis.
    echo "      omis : le guard de $SITE est dans la configuration serveur"
else
cp "$ROOT/$SITE/.htaccess" "$ROOT/$SITE/.htaccess.block" || exit 1
restore_block() {
    if [ -f "$ROOT/$SITE/.htaccess.block" ]; then
        mv "$ROOT/$SITE/.htaccess.block" "$ROOT/$SITE/.htaccess"
    fi
}
trap restore_block EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
sed -i 's/^#SetEnvIf Request_URI ^ MPG_OBSERVE=1/SetEnvIf Request_URI ^ MPG_OBSERVE=1/' "$ROOT/$SITE/.htaccess" || exit 1
check O1 PASS:article.php "multipart interdit : transmis"       -- r POST $S/article.php canary.bin "$CT"
check O2 PASS:upload.php  "chunked autorisé : transmis"         -- c -H 'Transfer-Encoding: chunked' -H "$CT" --data-binary @canary.bin "$BASE/upload.php"
obs=$(r POST $S/article.php canary.bin "$CT" | grep -o 'mpg=[^ ]*')
check O3 PASS:article.php "GET inchangé"                        -- c "$BASE/article.php"
if [ "$VARIANT" != rewrite ]; then
    check O5 LIMIT:article.php "POST 9 Mo chunked : limite encore active" -- c --data-binary @big9.txt -H 'Transfer-Encoding: chunked' "$BASE/article.php"
fi
restore_block || exit 1
trap - EXIT INT TERM
echo "      décision visible côté PHP en OBSERVE : $obs (attendu : mpg=deny_not_allowed)"
[ "$obs" = "mpg=deny_not_allowed" ] && pass=$((pass+1)) || { fail=$((fail+1)); failed+=(O4); }
fi

echo
echo "=== Résultat ($VARIANT, $SITE) : $pass OK, $fail ECHEC ${failed[*]:+— échecs : ${failed[*]}}"
[ $fail -eq 0 ]
