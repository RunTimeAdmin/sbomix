# sbomix — from npm install to a full SBOM in seconds.
# Rendered with vhs (https://github.com/charmbracelet/vhs): every command
# below actually runs; nothing is edited or sped up by hand.

Output sbomix-demo.gif

Set Shell bash
Set FontSize 20
Set Width 1200
Set Height 720
Set Padding 24
Set Theme "Dracula"
Set TypingSpeed 55ms

# --- hidden setup (not shown): a sample project + a local-network TLS
#     workaround so the container can reach the npm registry. A real user
#     on a normal network runs only the visible commands below. ---
Hide
Type "npm config set strict-ssl false" Enter
Type "mkdir -p /demo && cd /demo" Enter
Type "printf 'flask==3.0.0\nrequests==2.31.0\nanthropic==0.40\n' > requirements.txt" Enter
Type "clear" Enter
Show

# --- the demo ---
Sleep 800ms
Type "cat requirements.txt" Sleep 400ms Enter
Sleep 1800ms

Type "npm install -g sbomix" Sleep 400ms Enter
Sleep 11s

Type "sbomix . --no-vulns" Sleep 400ms Enter
Sleep 3500ms

Type "ls" Sleep 400ms Enter
Sleep 2500ms

Type "head -18 bom.cyclonedx.json" Sleep 400ms Enter
Sleep 3500ms
