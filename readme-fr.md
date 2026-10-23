# Multipart Guard

*[English version](readme.md)*

> **Document de travail expérimental, partagé tel quel.** Aucun support, aucune maintenance,
> aucune garantie : les tickets et demandes ne recevront pas de réponse. Ce
> n'est **pas** un correctif de sécurité. Lisez-le, testez-le sur vos propres
> serveurs avant usage, et mettez PHP à jour. Les résultats concernent
> uniquement les environnements de test décrits et ne garantissent pas une
> protection. Licence : [0BSD](LICENSE).

Réalisé avec GPT sol 6.1 medium && Claude Opus 5.5 medium.

Un petit jeu de règles Apache 2.4 qui **bloque les envois de fichiers sur
toutes les URL d'un site, sauf celles que vous autorisez**. Les requêtes
bloquées n'atteignent jamais PHP.

Pourquoi : en octobre 2026, deux failles critiques de PHP ont été publiées
(CVE-2026-109618 et CVE-2026-109619, « PHP2Shell »). L'un des principaux
chemins d'attaque passe par la façon dont PHP lit les envois de fichiers
(`multipart/form-data`). PHP les lit **avant** que le code de l'application
ne s'exécute : l'application ne peut donc pas se protéger elle-même. La
plupart des URL d'un site ne reçoivent jamais d'envoi de fichier : Apache
peut donc les refuser.

> **Ce n'est pas un correctif.** Seule la mise à jour de PHP corrige les
> failles. Multipart Guard supprime un chemin d'attaque sur la plupart des
> URL et rend les URL d'envoi autorisées plus difficiles à exploiter. Voir
> [Limites](#limites).

- Aucun module supplémentaire, aucun proxy, aucune modification du code PHP.
- Fonctionne avec mod_php, FastCGI (mod_fcgid) et PHP-FPM.
- Un seul fichier à copier : [`guard/multipart-guard.htaccess`](guard/multipart-guard.htaccess)
  (court, prêt à coller). Chaque ligne est expliquée dans
  [`guard/multipart-guard-doc.htaccess`](guard/multipart-guard-doc.htaccess)
  (mêmes règles ; commentaires en anglais).

---

## Démarrage rapide

1. **Vérifiez comment PHP est branché sur Apache** (voir
   [Où installer](#où-installer)). Avec PHP-FPM branché par
   `ProxyPassMatch`, le `.htaccess` **ne fonctionne pas** : installez dans le
   VirtualHost.
2. Copiez tout le contenu de `guard/multipart-guard.htaccess` **en tête** du
   `.htaccess` principal du site.
3. Dans la section **SETTINGS** :
   - activez le mode OBSERVE (retirez le `#` devant la ligne `MPG_OBSERVE`) ;
   - réglez la taille maximale d'envoi ;
   - listez les URL qui reçoivent vraiment des fichiers.
4. Installez le journal ([Journal](#journal)) et utilisez le site
   normalement pendant quelques jours.
5. Lisez le journal, corrigez la liste des URL autorisées, puis repassez en
   mode BLOCK (remettez le `#`).

Les modifications du `.htaccess` s'appliquent immédiatement, sans
redémarrage.

---

## Réglages

Tous les réglages sont en haut de `guard/multipart-guard.htaccess`. Ne modifiez pas la
section ENGINE.

### 1. Mode

| Mode | Effet |
|---|---|
| **BLOCK** (par défaut) | Les envois interdits reçoivent `403 Forbidden`. |
| **OBSERVE** | Les décisions sont seulement journalisées. `LimitRequestBody` reste actif. |

```apache
#SetEnvIf Request_URI ^ MPG_OBSERVE=1     <- BLOCK   (ligne commentée)
SetEnvIf Request_URI ^ MPG_OBSERVE=1      <- OBSERVE (ligne active)
```

**OBSERVE ne désactive pas tous les contrôles.** Il ignore le refus à
l'étape d'autorisation, mais Apache limite toujours les corps POST avec
`LimitRequestBody`. Les gros corps peuvent encore recevoir une 413 ou
arriver tronqués à FastCGI. Les règles d'accès du site restent également
actives.

### 2. Taille maximale des POST

En octets, chiffres uniquement. En mode BLOCK, un POST dont la taille
déclarée dépasse cette limite est refusé avant l'exécution de PHP : les
envois de fichiers (même sur les URL autorisées), les formulaires classiques,
le JSON, etc. Les corps POST sans taille déclarée sont limités pendant leur
lecture ; FastCGI peut recevoir un corps tronqué. PUT et PATCH ne sont pas
concernés.

Deux lignes, **le même nombre sur les deux** :

```apache
SetEnvIf Request_URI ^ MPG_MAX_BYTES=8323072
<If "%{REQUEST_METHOD} == 'POST'">
    LimitRequestBody 8323072
</If>
```

- La ligne 1 contrôle la taille déclarée (`Content-Length`) : refus en
  403/413, PHP n'est jamais appelé.
- La ligne 2 limite les corps sans taille déclarée (« chunked ») : 413
  avec mod_php, ou corps tronqué transmis à PHP avec les branchements
  FastCGI testés.

**Prenez le `post_max_size` de PHP moins 64 Ko.** Quand un corps POST dépasse
`post_max_size`, PHP écrit un avertissement (`POST Content-Length of … bytes
exceeds the limit`) *avant* l'exécution du script. Ce type d'avertissement
précoce fait partie du chemin d'attaque de CVE-2026-109619. Avec ce réglage,
Apache refuse ces requêtes en premier et l'avertissement n'a jamais lieu
(testé avec mod_php, mod_fcgid et proxy_fcgi). La marge de 64 Ko est
nécessaire pour les corps chunked : Apache les arrête quelques Ko après la
limite (jusqu'à 8 Ko mesurés avec mod_fcgid).

| `post_max_size` | Valeur pour les deux lignes |
|---|---|
| `2M` | `2031616` |
| `8M` (défaut PHP) | `8323072` |
| `10M` | `10420224` |
| `20M` | `20905984` |
| `50M` | `52363264` |
| `100M` | `104792064` |

Formule : `M × 1048576 − 65536`. Si plusieurs versions ou pools PHP servent
le site, prenez la plus petite valeur.

Si la ligne 1 est mal écrite (par exemple `10M`) ou manque, **tous les envois
de fichiers sont refusés** (le guard bloque, il ne s'ouvre jamais), mais les
formulaires classiques continuent de fonctionner : une faute de frappe ne
peut pas mettre tout le site hors service.

### 3. URL d'envoi autorisées

Une ligne par URL. Ne modifiez que le texte entre les apostrophes. Le fichier
n'est livré qu'avec des exemples, commentés : **sans aucune URL autorisée,
tous les envois de fichiers sont bloqués**.

```apache
SetEnvIfExpr "%{REQUEST_URI} == '/upload.php'"  MPG_ALLOWED=1
```

Ne mettez pas de commentaire en fin de ligne : Apache le lirait comme une
partie de la directive. Mettez les commentaires sur une ligne à part.

**WordPress.** Les URL d'envoi ci-dessous ont été vérifiées dans le code
source de WordPress 7.1 et testées avec le guard. Elles sont dans les deux
fichiers du guard, commentées : retirez le `#` des lignes utiles.

| Envoi | URL (WordPress à la racine du domaine) | Nécessaire |
|---|---|---|
| Médiathèque | `/wp-admin/async-upload.php` | presque toujours |
| Éditeur de blocs | `/wp-json/wp/v2/media` | presque toujours |
| Éditeur de blocs, tailles d'image supplémentaires | `^/wp-json/wp/v2/media/[0-9]+/sideload$` (motif) | presque toujours |
| Enregistrement des menus (thèmes classiques) | `/wp-admin/nav-menus.php` | thèmes classiques |
| Envoi d'un ZIP d'extension ou de thème | `/wp-admin/update.php` | si utilisé |
| Médias > Ajouter, envoi par le navigateur | `/wp-admin/media-new.php` | si utilisé |
| Ancienne fenêtre des médias | `/wp-admin/media-upload.php` | si utilisé |
| En-tête / arrière-plan personnalisé | `/wp-admin/themes.php` | thèmes classiques |
| Outils > Importer | `/wp-admin/admin.php` (large : toutes les pages d'extensions) | seulement pendant l'import |
| Multisite, ajout d'un site | `/wp-admin/network/site-new.php` | multisite |

- **Permaliens « simples » :** l'API REST passe par
  `/index.php?rest_route=/wp/v2/media`. Le fichier documenté contient une
  ligne prête pour ce cas (chemin `/index.php` + contrôle strict de la query
  string).
- **WordPress dans un sous-dossier :** ajoutez le dossier devant chaque
  chemin.
- **Extensions avec formulaires d'envoi publics** (formulaires de contact,
  etc.) : elles utilisent leurs propres URL, par exemple
  `/wp-json/contact-form-7/v1/contact-forms/<id>/feedback` ou
  `/wp-admin/admin-ajax.php`. Trouvez-les avec le mode OBSERVE.
- Autoriser une URL de `wp-admin` **n'exige pas** d'être connecté pour
  atteindre l'analyseur d'envois de PHP : PHP analyse l'envoi avant que
  WordPress ne vérifie la connexion. Protégez `/wp-admin/` par adresse IP ou
  mot de passe si possible.

**Comment écrire une URL**

| Règle | Exemple |
|---|---|
| Le chemin seul, commençant par `/`. Pas de domaine, pas de `?query`. | `https://example.org/blog/upload.php?id=3` → `'/blog/upload.php'` |
| Correspondance exacte. Pas de joker. | `'/upload.php'` n'autorise pas `'/upload.php/x'` |
| Les majuscules comptent. | `'/Upload.php'` ≠ `'/upload.php'` |
| Le `/` final compte. | `'/api/upload'` ≠ `'/api/upload/'` |
| Incluez le sous-dossier si le site est dans un sous-dossier. | `'/blog/wp-admin/async-upload.php'` |
| Utilisez l'URL envoyée par le **navigateur**, même si le site la réécrit vers `index.php`. | `'/wp-json/wp/v2/media'` |

Pour trouver la bonne URL : ouvrez les outils de développement du navigateur
(F12 → Réseau), envoyez un fichier et regardez le chemin de la requête. Ou
utilisez le mode OBSERVE et lisez le journal.

**Bonnes pratiques**

- Autorisez le moins d'URL possible.
- N'autorisez une URL que si vous savez que c'est un vrai formulaire d'envoi.
  **N'autorisez jamais une URL simplement parce qu'elle apparaît dans le
  journal** : n'importe qui peut envoyer des requêtes qui l'y font
  apparaître.
- Une URL oubliée ne casse que ce formulaire d'envoi. Elle n'affaiblit
  jamais la protection.

**Avancé : motifs.** Pour les URL qui contiennent une partie variable, on
peut utiliser une expression régulière. Commencez toujours par `^` et
terminez par `$` :

```apache
SetEnvIfExpr "%{REQUEST_URI} =~ m#^/api/items/[0-9]+/upload$#"  MPG_ALLOWED=1
```

---

## Où installer

Cela dépend de la façon dont PHP est branché sur Apache :

| Branchement PHP | Dans le `.htaccess` | Dans le VirtualHost, `<Location "/">` |
|---|---|---|
| mod_php | ✅ | ✅ |
| mod_fcgid (`FcgidWrapper`) | ✅ | ✅ |
| PHP-FPM avec `SetHandler "proxy:fcgi://..."` | ✅ | ✅ |
| PHP-FPM avec **`ProxyPassMatch`** | ❌ **ignoré** | ✅ |

Avec `ProxyPassMatch`, Apache envoie la requête à PHP-FPM avant de regarder
les dossiers du site : **les fichiers `.htaccess` ne sont jamais lus**.
Testé : l'envoi atteint PHP, même vers un script qui n'existe pas.

Pour vérifier un serveur Linux (commande en lecture seule) :

```sh
grep -rn "ProxyPassMatch\|SetHandler.*proxy:" /etc/apache2/sites-enabled/
```

**Recommandé : installer dans le VirtualHost.** Cela fonctionne dans tous
les cas et ne dépend pas des fichiers `.htaccess`.

### Dans un VirtualHost

Enregistrez `guard/multipart-guard.htaccess` (avec vos réglages) sous, par exemple,
`/etc/apache2/multipart-guard/example.org.conf`, puis ajoutez dans
**chaque** VirtualHost du site (`:80` et `:443`) :

```apache
<VirtualHost *:443>
    ServerName example.org
    ...
    <Location "/">
        Include /etc/apache2/multipart-guard/example.org.conf
    </Location>
</VirtualHost>
```

Puis vérifiez et rechargez :

```sh
apachectl configtest && systemctl reload apache2
```

Dans `<Location>`, les règles se comportent exactement comme dans un
`.htaccess` (testé). Changer le mode ou la liste des URL demande un
rechargement.

### Dans un .htaccess

À utiliser seulement si vous ne pouvez pas modifier le VirtualHost, et
seulement si PHP n'est pas branché par `ProxyPassMatch`. Il faut un
`AllowOverride` incluant au moins `FileInfo` et `AuthConfig` (ou `All`).

Le `.htaccess` d'un sous-dossier ne peut pas désactiver le guard par
accident (testé avec `RewriteEngine On`, `RewriteEngine Off` et
`ErrorDocument`). Mais quiconque peut **écrire** un `.htaccess` peut le
retirer.

---

## Journal

[`apache/multipart-guard-log.conf`](apache/multipart-guard-log.conf) écrit
une ligne par requête d'envoi, pour tous les sites. Ce fichier doit aller
dans la configuration **serveur** (pas dans un `.htaccess`) :

- **Debian/Ubuntu :** copiez-le dans `/etc/apache2/conf-available/`, puis
  `a2enconf multipart-guard-log && systemctl reload apache2`.
  Dans le fichier, remplacez le chemin du journal par
  `${APACHE_LOG_DIR}/multipart-guard.log`.
- **WAMP :** copiez-le dans `c:/wamp64/alias/` et redémarrez Apache.

Exemple :

```text
2026-10-22T15:24:58+0200 MULTIPART_GUARD action=deny_not_allowed observe=- status=403 ip=203.0.113.7 peer=203.0.113.7 host=example.org method=POST uri="/article.php" ctype="multipart/form-data; boundary=XyZ" cl=2133 te=-
```

- Une ligne par événement, au format `clé=valeur` : facile à filtrer avec
  `grep` et à utiliser plus tard avec Fail2ban.
- Les corps de requête, les query strings et les cookies ne sont jamais
  enregistrés.
- En mode OBSERVE, `observe=1` et `status` vaut en général `200` : la ligne
  montre ce qui *aurait* été bloqué.
- **Derrière un reverse proxy** (CDN, répartiteur de charge), `ip` n'est le
  vrai client que si `mod_remoteip` est configuré avec `RemoteIPHeader` et
  `RemoteIPTrustedProxy`. `peer` est toujours l'adresse de la connexion TCP.

Chaque blocage écrit aussi `AH01630: client denied by server configuration`
dans le journal d'erreurs d'Apache.

---

## Comment le guard décide

Pour chaque requête dont le `Content-Type` contient `multipart` (sans tenir
compte de la casse), la première règle qui correspond l'emporte :

| Ordre | Contrôle | `action` dans le journal |
|---|---|---|
| 1 | L'URL n'est pas dans la liste autorisée | `deny_not_allowed` |
| 2 | La méthode n'est pas POST | `deny_method` |
| 3 | Le `Content-Type` n'est pas exactement `multipart/form-data; boundary=...` | `deny_bad_ctype` |
| 4 | Pas d'en-tête `Content-Length` (corps chunked) | `deny_no_length` |
| 5 | `Content-Length` dépasse la limite | `deny_too_large` |
| – | Tous les contrôles sont passés | `allow` |

Tout autre POST (formulaire, JSON…) dont le `Content-Length` dépasse la
limite est aussi refusé, avec `action=deny_too_large`.

Pourquoi ces contrôles :

- **Détection large.** PHP considère aussi `multipart/form-data,x` et
  `multipart/form-data x` comme des envois de fichiers (testé). Un motif
  strict comme `^multipart/form-data(;|$)` les laisserait passer. Tout ce
  qui contient `multipart` est donc intercepté.
- **Format strict sur les URL autorisées.** Les navigateurs envoient
  toujours un seul en-tête propre. Tout le reste (en-tête en double,
  paramètre en plus) est suspect. Par exemple, PHP cherche le boundary dans
  le texte : avec `xboundary=AAA; boundary=XyZ`, PHP utilise `AAA`.
- **`Content-Length` obligatoire, avec une limite.** CVE-2026-109618 peut
  exploiter des corps envoyés sans longueur déclarée. Apache ne transmet
  jamais à PHP plus de `Content-Length` octets : la limite est donc réelle.
- **Requête d'origine uniquement.** Une URL « propre » que le site réécrit
  vers `index.php` reste autorisée. Une URL interdite est refusée avant
  toute réécriture.
- **Une requête refusée reste refusée**, même si un `ErrorDocument` pointe
  vers un script PHP.

Le blocage a lieu à l'étape d'autorisation d'Apache, **avant que PHP ne soit
appelé**.

---

## Dépannage

**Un formulaire d'envoi reçoit maintenant une 403.** Regardez la ligne du
journal correspondant à cette requête :

| `action` | Signification | Que faire |
|---|---|---|
| `deny_not_allowed` | URL absente de la liste | Vérifiez le chemin exact (casse, `/` final, sous-dossier) et ajoutez-le. |
| `deny_method` | Pas un POST | En général un client d'API. Vérifiez qu'il est légitime. |
| `deny_bad_ctype` | `Content-Type` inhabituel | Certains clients non navigateurs ajoutent des paramètres. Regardez le champ `ctype`. |
| `deny_no_length` | Corps envoyé en « chunked » | Certaines applis mobiles ou scripts le font. Les navigateurs jamais. |
| `deny_too_large` | Fichier trop gros | Augmentez `MPG_MAX_BYTES` si nécessaire. |

**Rien n'est journalisé.** Le journal fait partie de la configuration
serveur : vérifiez qu'il est installé et qu'Apache a été redémarré. Avec un
`.htaccess`, vérifiez aussi que le guard est bien en tête et que le site
n'utilise pas `ProxyPassMatch`.

---

## Désinstallation

- `.htaccess` : supprimez le bloc. Effet immédiat.
- VirtualHost : retirez les lignes `Include`, puis
  `apachectl configtest && systemctl reload apache2`.
- Journal : supprimez le fichier (ou `a2disconf multipart-guard-log`) et
  rechargez Apache.

---

## Limites

- **Les URL autorisées restent exposées.** Un attaquant peut envoyer un
  fichier malveillant vers une URL autorisée. Le guard ne limite que sa
  taille et son format. Une petite requête peut quand même consommer
  beaucoup de mémoire dans PHP.
- **CVE-2026-109619 n'est presque pas couverte.** Ses chemins principaux
  (erreurs fatales pendant l'exécution du script, avertissements précoces
  de la configuration PHP) ne passent pas par les envois de fichiers.
- **Les autres attaques ne sont pas couvertes** : tout ce qui n'utilise pas
  d'envoi de fichier.
- **Faux positifs possibles** sur les URL autorisées : clients qui envoient
  en chunked, paramètres supplémentaires dans `Content-Type`, ou méthode
  autre que POST. Commencez par le mode OBSERVE.
- Testé sous Windows (WAMP). Les tests « PHP-FPM » utilisent `php-cgi` comme
  serveur FastCGI séparé, pas le vrai PHP-FPM. Comme le filtrage a lieu dans
  Apache, les résultats devraient être identiques, mais une vérification
  sous Linux avec PHP-FPM est recommandée.

**À faire aussi :** mettre PHP à jour, régler
`session.upload_progress.enabled = Off` et suivre les avis officiels de PHP.

---

## Tests

### Comment on prouve que PHP n'a rien reçu

Le corps de test [`tests/canary.bin`](tests/canary.bin) contient 21 fichiers,
alors que PHP en accepte 20 (`max_file_uploads = 20`). Si l'analyseur
d'envois de PHP voit la requête, PHP écrit un avertissement dans
`php_error.log` **pendant l'analyse, avant tout script**. Un blocage n'est
validé que si :

1. le code est 403 (ou 413 pour un corps trop gros) ;
2. aucun script PHP ne s'est exécuté ;
3. aucun nouvel avertissement n'est apparu.

Les tests de taille reposent sur la même idée : PHP écrit un avertissement
*avant* le script quand un corps POST dépasse `post_max_size` (8M sur WAMP).
Pas d'avertissement = PHP n'a jamais vu de corps trop gros.

Le test témoin A2 (URL autorisée) exige à la fois l'exécution du script
attendu et un nouvel avertissement multipart. Un journal PHP absent ou
illisible interrompt la suite. Pour un gros POST chunked, le test exige
soit une 413 sans marqueur PHP, soit une 200/413 du script attendu avec une
taille de corps mesurée ne dépassant pas le `post_max_size` du banc (8M).
Une erreur de connexion ne peut pas valider ce contrôle.

### Lancer les tests

Le banc de test est écrit pour **WAMP sous Windows** (Git Bash) : le projet
doit se trouver dans `c:/wamp64/www/multipart2hell/`, et le script utilise
les chemins PHP et journaux de WAMP (variables en haut de
`tests/run-tests.sh`). Le guard lui-même n'a aucune de ces dépendances.

```sh
bash tests/run-tests.sh multipart-guard site          # mod_php
bash tests/run-tests.sh multipart-guard site-fcgi     # FastCGI (mod_fcgid + php-cgi 7.4)
bash tests/run-tests.sh multipart-guard site-fpm      # type PHP-FPM, SetHandler
bash tests/run-tests.sh multipart-guard site-ppm      # type PHP-FPM, ProxyPassMatch
bash tests/run-tests.sh rewrite site       # édition mod_rewrite, pour comparaison
```

Le script écrit le `.htaccess` du site de test (guard + handler PHP + règles
de l'application) et le laisse en place. `site-fpm` et `site-ppm` demandent
`apache/fpm-test.conf` dans `c:/wamp64/alias/` (puis un redémarrage
d'Apache) et un serveur FastCGI séparé :

```sh
cd /c/wamp64/bin/php/php7.4.33 && PHP_FCGI_MAX_REQUESTS=0 ./php-cgi.exe -b 127.0.0.1:9074
```

### Ce qui est testé

- **Le trafic normal est inchangé :** GET, formulaires, JSON, texte brut,
  PUT, corps chunked.
- **Envois vers des URL interdites, sous toutes leurs formes :** casse
  inhabituelle, `,x`, espaces, en-têtes repliés, en-têtes en double,
  chunked, PUT/PATCH, `multipart/mixed`, URL réécrites, sous-dossiers,
  `ErrorDocument`.
- **Astuces de chemin autour des URL autorisées :** `PATH_INFO`, casse,
  `//`, `/./`, `%2e`, `../`, MultiViews, `::$DATA`, point final, octet nul,
  URL absolue.
- **URL autorisées :** seul le format navigateur passe.
- **Taille des POST :** formulaires et JSON de 9 Mo refusés, corps chunked
  de 9 Mo jamais vu en entier par PHP, corps de 8 Mo et gros PUT inchangés.
- **Mode OBSERVE**, y compris la limite de corps POST qui reste active.
- **Guillemets non appariés du boundary** refusés sur les URL autorisées.

### Résultats (WAMP, Apache 2.4.58, Windows)

Tests locaux du 23 octobre 2026, après la correction des guillemets du
boundary et le renforcement des contrôles des tests. Les deux éditions
distribuées ont été testées séparément.

| Édition | mod_php 8.4.25 | mod_fcgid 7.4.33 | type FPM, `SetHandler` | type FPM, `ProxyPassMatch` |
|---|---|---|---|---|
| `expr` dans le `.htaccess` (deux éditions) | **71/71 chacune** | **71/71 chacune** | **71/71 chacune** | ❌ ignoré |
| `expr` dans `<Location>` | – | – | – | **66/66** (OBSERVE non testé) |
| `rewrite` dans le `.htaccess` | 61/62 (version précédente, sans les tests de taille POST) | 61/62 | 61/62 | ❌ ignoré |

Les résultats `rewrite` sont historiques et n'ont pas été reproduits pour
cette révision. L'édition `rewrite` échoue au test M19 : un sous-dossier contenant
`RewriteEngine Off` la désactive. C'est pourquoi l'édition recommandée
n'utilise pas mod_rewrite. Elle n'a pas non plus de contrôle de taille des
POST.

Avec un corps chunked au-delà de la limite, mod_php répond 413 et peut
quand même exécuter le script avec un corps tronqué. mod_fcgid et
proxy_fcgi répondent 200 avec un corps tronqué. Les tests vérifient la
taille mesurée lorsqu'un script s'exécute, ainsi que l'absence
d'avertissement PHP de dépassement de taille.

Le premier passage `ProxyPassMatch` utilisait une ancienne configuration
encore chargée dans Apache. Après le redémarrage par le propriétaire,
les 66 tests passent avec le fichier inclus actuel, y compris les guillemets
incomplets et les gros POST avec taille déclarée. OBSERVE n'a pas été testé
pour ce branchement, car le changement de mode demande un rechargement.
Voir le [rapport de test](tests/wamp-results-2026-10-23.md).

---

## Fichiers du projet

| Fichier | Rôle |
|---|---|
| [`guard/multipart-guard.htaccess`](guard/multipart-guard.htaccess) | **Le guard**, prêt à copier-coller |
| [`guard/multipart-guard-doc.htaccess`](guard/multipart-guard-doc.htaccess) | Mêmes règles, avec toutes les explications |
| [`guard/rewrite.htaccess`](guard/rewrite.htaccess) | Édition mod_rewrite, pour comparaison uniquement |
| [`apache/multipart-guard-log.conf`](apache/multipart-guard-log.conf) | Journal dédié (configuration serveur) |
| [`apache/fpm-test.conf`](apache/fpm-test.conf) | Banc de test pour les configurations type PHP-FPM |
| `site/` | Site de test, PHP par mod_php |
| `site-fcgi/` | Même site, PHP par mod_fcgid + php-cgi 7.4 |
| `site-fpm/` | Même site, PHP par mod_proxy_fcgi + `SetHandler` |
| `site-ppm/` | Même site, PHP par mod_proxy_fcgi + `ProxyPassMatch` (guard dans `<Location>`) |
| `control/` | Dossier non protégé, pour voir ce que PHP accepte lui-même |
| [`tests/run-tests.sh`](tests/run-tests.sh) | Tests automatisés (curl + client brut) |
| [`tests/raw.php`](tests/raw.php) | Client HTTP brut (en-têtes en double, repliés, etc.) |
