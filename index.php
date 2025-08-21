<?php
// crypto_tool_server.php — Vollansicht + Widget (?embed=1)
declare(strict_types=1);
mb_internal_encoding('UTF-8');

$isEmbed = isset($_GET['embed']) && $_GET['embed'] == '1';

/* ---------- Security / Caching ---------- */
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: ' . ($isEmbed ? 'ALLOWALL' : 'DENY')); // Widget darf in iframes laufen
header('Cross-Origin-Opener-Policy: same-origin');
header('Cross-Origin-Resource-Policy: same-origin');
header("Content-Security-Policy: default-src 'self'; img-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline';");
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

ini_set('display_errors', '0');

session_start();
if (empty($_SESSION['csrf'])) { $_SESSION['csrf'] = bin2hex(random_bytes(16)); }

function h(?string $s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

/* ---------- Helpers (Base64URL) ---------- */
function b64u_enc(string $bin): string { return rtrim(strtr(base64_encode($bin), '+/', '-_'), '='); }
function b64u_dec(string $b64u): string {
  $b64 = strtr($b64u, '-_', '+/'); $pad = strlen($b64) % 4; if ($pad) $b64 .= str_repeat('=', 4-$pad);
  $out = base64_decode($b64, true); if ($out === false) throw new InvalidArgumentException('Base64 fehlerhaft.'); return $out;
}

/* ---------- Crypto ---------- */
function have_sodium(): bool {
  return extension_loaded('sodium')
    && function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt')
    && function_exists('sodium_crypto_pwhash');
}
function enc_sodium(string $plain, string $password): string {
  $ops = SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE;
  $mem = SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE;
  $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
  $key  = sodium_crypto_pwhash(
    SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
    $password, $salt, $ops, $mem, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
  );
  $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
  $ct = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plain, '', $nonce, $key); // ct||tag
  $pkg = ['v'=>1,'kdf'=>'argon2id','ops'=>$ops,'mem'=>$mem,'alg'=>'xchacha20poly1305',
          'salt'=>b64u_enc($salt),'nonce'=>b64u_enc($nonce),'ct'=>b64u_enc($ct)];
  return base64_encode(json_encode($pkg, JSON_UNESCAPED_SLASHES));
}
function dec_sodium(string $blob, string $password): string {
  $json = base64_decode($blob, true); if ($json === false) throw new InvalidArgumentException('Kein gültiges Base64.');
  $p = json_decode($json, true);
  foreach (['v','kdf','ops','mem','alg','salt','nonce','ct'] as $f) if (!isset($p[$f])) throw new InvalidArgumentException("Feld fehlt: $f");
  if ($p['v']!==1 || $p['kdf']!=='argon2id' || $p['alg']!=='xchacha20poly1305') throw new InvalidArgumentException('Paketformat nicht unterstützt.');
  $key = sodium_crypto_pwhash(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES, $password, b64u_dec($p['salt']),
                              (int)$p['ops'], (int)$p['mem'], SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
  $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(b64u_dec($p['ct']), '', b64u_dec($p['nonce']), $key);
  if ($plain === false) throw new RuntimeException('Entschlüsselung fehlgeschlagen (Passwort/Daten).'); return $plain;
}
function enc_openssl(string $plain, string $password): string {
  $alg = 'aes-256-gcm'; $iv = random_bytes(12); $salt=random_bytes(16); $iter=150000;
  $key = hash_pbkdf2('sha256', $password, $salt, $iter, 32, true);
  $tag=''; $ct = openssl_encrypt($plain,$alg,$key,OPENSSL_RAW_DATA,$iv,$tag);
  if ($ct===false) throw new RuntimeException('OpenSSL-Verschlüsselung fehlgeschlagen.');
  $pkg = ['v'=>1,'kdf'=>'pbkdf2','iter'=>$iter,'alg'=>'aes-256-gcm',
          'salt'=>b64u_enc($salt),'iv'=>b64u_enc($iv),'tag'=>b64u_enc($tag),'ct'=>b64u_enc($ct)];
  return base64_encode(json_encode($pkg, JSON_UNESCAPED_SLASHES));
}
function dec_openssl(string $blob, string $password): string {
  $json = base64_decode($blob, true); if ($json === false) throw new InvalidArgumentException('Kein gültiges Base64.');
  $p = json_decode($json,true);
  foreach (['v','kdf','iter','alg','salt','iv','tag','ct'] as $f) if (!isset($p[$f])) throw new InvalidArgumentException("Feld fehlt: $f");
  if ($p['v']!==1 || $p['kdf']!=='pbkdf2' || $p['alg']!=='aes-256-gcm') throw new InvalidArgumentException('Paketformat nicht unterstützt.');
  $key = hash_pbkdf2('sha256',$password,b64u_dec($p['salt']),(int)$p['iter'],32,true);
  $plain = openssl_decrypt(b64u_dec($p['ct']),'aes-256-gcm',$key,OPENSSL_RAW_DATA,b64u_dec($p['iv']),b64u_dec($p['tag']));
  if ($plain === false) throw new RuntimeException('Entschlüsselung fehlgeschlagen (Passwort/Daten).'); return $plain;
}
function encrypt_pkg(string $plain, string $password): string { return have_sodium() ? enc_sodium($plain,$password) : enc_openssl($plain,$password); }
function decrypt_pkg_auto(string $blob, string $password): string {
  $json = base64_decode($blob, true); if ($json === false) throw new InvalidArgumentException('Kein gültiges Base64.');
  $p = json_decode($json, true); if (!is_array($p) || empty($p['kdf']) || empty($p['alg'])) throw new InvalidArgumentException('Unbekanntes Paket.');
  if ($p['kdf']==='argon2id' && $p['alg']==='xchacha20poly1305') { if (!have_sodium()) throw new InvalidArgumentException('Sodium nicht verfügbar.'); return dec_sodium($blob,$password); }
  if ($p['kdf']==='pbkdf2'  && $p['alg']==='aes-256-gcm') return dec_openssl($blob,$password);
  throw new InvalidArgumentException('Dieses Paket kann hier nicht entschlüsselt werden.');
}

/* ---------- Request ---------- */
$mode = $_POST['mode'] ?? 'enc';
$input = (string)($_POST['input'] ?? '');
$password = (string)($_POST['password'] ?? '');

$result = ''; $error=''; $okMsg='';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  try {
    if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) throw new RuntimeException('Ungültiges Formular (CSRF).');
    if ($password === '') throw new InvalidArgumentException('Bitte ein Passwort eingeben.');
    if ($mode === 'enc') { $result = encrypt_pkg($input, $password); $okMsg = 'Verschlüsselung erfolgreich.'; }
    elseif ($mode === 'dec') { $result = decrypt_pkg_auto(trim($input), $password); $okMsg = 'Entschlüsselung erfolgreich.'; }
    else throw new InvalidArgumentException('Unbekannter Modus.');
  } catch (Throwable $e) { $error = $e->getMessage(); }
}

/* ---------- Hilfen für Snippet ---------- */
$scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
$host   = $_SERVER['HTTP_HOST'] ?? 'localhost';
$path   = strtok($_SERVER['REQUEST_URI'], '?') ?: '/crypto_tool_server.php';
$widgetUrl = $scheme.'://'.$host.$path.'?embed=1';

/* ---------- View ---------- */
?>
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title><?= $isEmbed ? 'Krypto-Widget' : 'Text verschlüsseln/entschlüsseln (Server)' ?></title>
<link rel="stylesheet" href="./style.css?v=<?= filemtime($_SERVER['DOCUMENT_ROOT'].'./style.css') ?>">
</head>
<body>
<div class="container"<?= $isEmbed ? ' style="max-width:700px;margin:0;padding:16px"' : '' ?>>
  <div class="card">
    <?php if (!$isEmbed): ?>
      <h1>🔐 Serverseitige Verschlüsselung <text class="small">(<?= have_sodium() ? 'libsodium: Argon2id + XChaCha20-Poly1305' : 'OpenSSL: PBKDF2 + AES-256-GCM' ?>)</text></h1>
    <?php else: ?>
      <h1 style="margin-bottom:8px;">🔐 Krypto-Widget<br><text class="small">(<?= have_sodium() ? 'libsodium: Argon2id + XChaCha20-Poly1305' : 'OpenSSL: PBKDF2 + AES-256-GCM' ?>)</text></h1>
    <?php endif; ?>

    <?php if ($error): ?><div class="error">⚠️ <?= h($error) ?></div><?php endif; ?>
    <?php if ($okMsg && !$error): ?><div class="ok">✅ <?= h($okMsg) ?></div><?php endif; ?>

    <form method="post" autocomplete="off" id="cryptoForm">
      <input type="hidden" name="csrf" value="<?= h($_SESSION['csrf']) ?>">

      <div class="row">
        <div>
          <label for="mode">Modus</label>
          <select id="mode" name="mode" onchange="switchLabels();sendHeight();">
            <option value="enc" <?= $mode==='enc'?'selected':'' ?>>Verschlüsseln → erzeugt Paket</option>
            <option value="dec" <?= $mode==='dec'?'selected':'' ?>>Entschlüsseln → Klartext anzeigen</option>
          </select>
        </div>
        <div>
          <label for="password">Passwort (Schlüsselwort)</label>
          <input id="password" name="password" type="password" placeholder="z. B. MeinGeheimesWort" required>
          <div class="toggle">
            <label class="switch">
                <input id="showPw" type="checkbox" onclick="togglePw()">
                <span class="slider"></span>
            </label>
            <span class="toggle-label">Passwort anzeigen</span>
          </div>
          <div class="small">Tipp: langes, einzigartiges Passwort verwenden.</div>
        </div>
      </div>

      <label for="input" id="inputLabel"><?= $mode==='dec' ? 'Eingabe (verschlüsseltes Paket, Base64)' : 'Eingabe (Klartext)' ?></label>
      <textarea id="input" name="input" spellcheck="false" placeholder="<?= $mode==='dec' ? 'Füge hier den Base64-String ein …' : 'Gib hier deinen Klartext ein …' ?>"><?= h($input) ?></textarea>

      <div class="actions">
        <button type="submit"><?= $mode==='dec' ? '🔓 Entschlüsseln' : '🔒 Verschlüsseln' ?></button>
        <button class="secondary" type="button" id="copyInBtn">📋 Eingabe kopieren</button>
        <button class="secondary" type="button" id="clearBtn">🧹 Leeren</button>
        <?php if (!$isEmbed): ?>
          <button class="secondary" type="button" id="resetBtn">🔄 Zurücksetzen</button>
        <?php endif; ?>
      </div>
    </form>

    <?php if ($result !== '' && !$error): ?>
      <div id="outWrap" style="margin-top:16px;">
        <label for="output" id="outLabel"><?= $mode==='dec' ? 'Ergebnis (Klartext)' : 'Ergebnis (verschlüsseltes Paket, Base64)' ?></label>
        <textarea id="output" readonly spellcheck="false"><?= h($result) ?></textarea>
        <div class="actions">
          <button id="copyOutBtn" type="button">📋 Ergebnis kopieren</button>
        </div>
        <?php if ($mode!=='dec'): ?>
          <div id="outHint" class="small">Speichere den obigen Base64-String. Zum Entschlüsseln denselben String + Passwort verwenden.</div>
        <?php endif; ?>
      </div>
    <?php endif; ?>

    <?php if (!$isEmbed): ?>
      <div class="footer">
        <p><strong>Paketformat:</strong>
          <?php if (have_sodium()): ?>
            Base64-JSON mit <code class="inline">salt</code>, <code class="inline">nonce</code>, <code class="inline">ct</code> (Ciphertext+Tag).
          <?php else: ?>
            Base64-JSON mit <code class="inline">salt</code>, <code class="inline">iv</code>, <code class="inline">tag</code>, <code class="inline">ct</code>.
          <?php endif; ?>
        </p>
        <p class="small">Verarbeitung serverseitig. Bitte über <strong>HTTPS</strong> nutzen.</p>
      </div>

      <hr style="border-color:#1f2937;margin:24px 0;">
      <h1>🔗 Einbettungs-Snippet</h1>
      <p class="small">Dieses Snippet bindet das Widget (iFrame) inkl. Auto-Höhe auf beliebigen Seiten ein.</p>
      <pre class="snippet" id="snippetBox">&lt;div id="crypto-widget"&gt;&lt;/div&gt;
&lt;script&gt;(function(){
  var el=document.getElementById('crypto-widget');
  var f=document.createElement('iframe');
  f.src='<?= h($widgetUrl) ?>';
  f.style.width='100%'; f.style.border='0'; f.setAttribute('title','Krypto-Widget');
  el.appendChild(f);
  function onMessage(e){
    if(!e.data || e.data.type!=='crypto-widget-height') return;
    if (e.origin!==location.origin) { /* optional: Origin prüfen */ }
    f.style.height=(e.data.value)+'px';
  }
  window.addEventListener('message', onMessage);
})();&lt;/script&gt;</pre>
      <div class="actions">
        <button type="button" class="secondary" id="copySnippet">📋 Snippet kopieren</button>
      </div>
    <?php endif; ?>
  </div>
</div>

<script>
function $(s){return document.querySelector(s);}
function togglePw(){ const el=$('#password'); el.type = el.type==='password'?'text':'password'; }
function switchLabels(){
  const isDec = $('#mode').value === 'dec';
  $('#inputLabel').textContent = isDec ? 'Eingabe (verschlüsseltes Paket, Base64)' : 'Eingabe (Klartext)';
  $('#input').placeholder      = isDec ? 'Füge hier den Base64-String ein …'     : 'Gib hier deinen Klartext ein …';
  const btn = document.querySelector('form button[type="submit"]');
  if (btn) btn.textContent = isDec ? '🔓 Entschlüsseln' : '🔒 Verschlüsseln';
}

/* Kopieren / Leeren / Reset */
$('#copyInBtn')?.addEventListener('click', ()=>{ const ta=$('#input'); ta.select(); document.execCommand('copy'); });
$('#copyOutBtn')?.addEventListener('click', ()=>{ const ta=$('#output'); if(!ta) return; ta.select(); document.execCommand('copy'); });
$('#clearBtn')?.addEventListener('click', ()=>{ $('#input').value=''; });
<?php if (!$isEmbed): ?>
$('#resetBtn')?.addEventListener('click', ()=>{ window.location.replace(window.location.pathname); });
$('#copySnippet')?.addEventListener('click', ()=>{ const ta=document.getElementById('snippetBox'); 
  const r=document.createRange(); r.selectNodeContents(ta); const s=window.getSelection(); s.removeAllRanges(); s.addRange(r); document.execCommand('copy'); s.removeAllRanges();
});
<?php endif; ?>

/* ===== iFrame Auto-Höhe (Widget) ===== */
function sendHeight(){
  try {
    var h = Math.max(document.body.scrollHeight, document.documentElement.scrollHeight);
    parent.postMessage({type:'crypto-widget-height', value:h}, '*'); // ggf. Origin statt '*'
  } catch(e){}
}
<?php if ($isEmbed): ?>
// im Widget: Höhe melden bei Load & Änderungen
window.addEventListener('load', sendHeight);
new ResizeObserver(sendHeight).observe(document.body);
<?php else: ?>
// in Vollansicht nichts senden
<?php endif; ?>
</script>
</body>
</html>
