package challenge

import (
	"strconv"
	"strings"
)

// buildChallengePage generates the HTML page with inline JavaScript that solves
// a SHA-256 proof-of-work puzzle. The browser must find a nonce such that
// SHA256(challenge + nonce) has `difficulty` leading zero bits.
func buildChallengePage(challenge string, difficulty int, redirectURI string) string {
	var b strings.Builder
	b.Grow(4096)

	// Escape the redirect URI for safe embedding in a JavaScript string
	safeRedirect := jsStringEscape(redirectURI)

	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Check — GuardianWAF</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;
min-height:100vh}
.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:48px;
max-width:480px;width:90%;text-align:center;box-shadow:0 25px 50px -12px rgba(0,0,0,.5)}
h1{font-size:1.5rem;margin-bottom:8px;color:#f8fafc}
.sub{color:#94a3b8;margin-bottom:32px;font-size:.9rem}
.spinner{width:48px;height:48px;border:4px solid #334155;border-top-color:#3b82f6;
border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 24px}
@keyframes spin{to{transform:rotate(360deg)}}
.progress{background:#334155;border-radius:8px;height:8px;overflow:hidden;margin:16px 0}
.bar{height:100%;background:linear-gradient(90deg,#3b82f6,#8b5cf6);border-radius:8px;
width:0%;transition:width .3s}
.status{color:#94a3b8;font-size:.85rem;margin-top:8px;min-height:1.2em}
.ok{color:#22c55e}
.err{color:#ef4444}
.shield{font-size:2.5rem;margin-bottom:16px}
noscript .nojs{background:#dc2626;color:#fff;padding:16px;border-radius:8px;margin-top:16px}
</style>
</head>
<body>
<div class="card">
<div class="shield">&#128737;</div>
<h1>Verifying your browser</h1>
<p class="sub">This is an automated security check. Please wait.</p>
<div class="spinner" id="spinner"></div>
<div class="progress"><div class="bar" id="bar"></div></div>
<p class="status" id="status">Initializing challenge...</p>
<noscript><div class="nojs">JavaScript is required to pass this security check.</div></noscript>
</div>
<script>
(function(){
"use strict";
var C="`)
	b.WriteString(challenge)
	b.WriteString(`",D=`)
	b.WriteString(strconv.Itoa(difficulty))
	b.WriteString(`,R="`)
	b.WriteString(safeRedirect)
	b.WriteString(`";
var status=document.getElementById("status"),
    bar=document.getElementById("bar"),
    spinner=document.getElementById("spinner");

// SHA-256 using Web Crypto API
async function sha256(msg){
var enc=new TextEncoder();
var buf=await crypto.subtle.digest("SHA-256",enc.encode(msg));
return new Uint8Array(buf);
}

// Check if hash has required leading zero bits
function checkZeros(hash,bits){
var full=bits>>>3,rem=bits&7;
for(var i=0;i<full;i++)if(hash[i]!==0)return false;
if(rem>0&&full<hash.length){
var mask=0xFF<<(8-rem);
if((hash[full]&mask)!==0)return false;
}
return true;
}

async function solve(){
status.textContent="Solving challenge (difficulty: "+D+" bits)...";
var batch=5000,n=0,maxN=1<<28;
while(n<maxN){
for(var i=0;i<batch;i++){
var nonce=n.toString(16);
var hash=await sha256(C+nonce);
if(checkZeros(hash,D)){
status.textContent="Verified! Redirecting...";
status.className="status ok";
bar.style.width="100%";
spinner.style.borderTopColor="#22c55e";
submit(nonce);
return;
}
n++;
}
var pct=Math.min(95,Math.floor((n/maxN)*100));
bar.style.width=pct+"%";
status.textContent="Working... "+n.toLocaleString()+" hashes computed";
}
status.textContent="Challenge failed. Please reload the page.";
status.className="status err";
}

function submit(nonce){
var form=document.createElement("form");
form.method="POST";
form.action="/__guardianwaf/challenge/verify";
var fields={challenge:C,nonce:nonce,redirect:R};
for(var k in fields){
var inp=document.createElement("input");
inp.type="hidden";inp.name=k;inp.value=fields[k];
form.appendChild(inp);
}
document.body.appendChild(form);
form.submit();
}

solve();
})();
</script>
</body>
</html>`)

	return b.String()
}

// jsStringEscape escapes a string for safe embedding inside a JavaScript
// double-quoted string literal within a <script> tag.
func jsStringEscape(s string) string {
	// Order matters: backslash first, then other escapes
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "'", `\'`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	// Prevent </script> injection by escaping forward slash after <
	s = strings.ReplaceAll(s, "</", `<\/`)
	// Escape Unicode line/paragraph separators (valid in JSON but terminate JS strings)
	s = strings.ReplaceAll(s, "\u2028", `\u2028`)
	s = strings.ReplaceAll(s, "\u2029", `\u2029`)
	return s
}
