"""Run the four-process Step 4 demonstration using temporary credentials."""
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import tempfile
import time

repo = Path(__file__).resolve().parents[1]
work = Path(tempfile.mkdtemp(prefix="perimeter-step4-demo."))
env = dict(os.environ, GOCACHE="/tmp/perimeter-go-cache")
children = []
logs = []

def run(args, cwd=repo):
    print("$ " + " ".join(map(str, args)), flush=True)
    result = subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True, timeout=60)
    print(result.stdout, end="" if not result.stdout or result.stdout.endswith("\n") else "\n", flush=True)
    if result.stderr:
        print(result.stderr, end="", flush=True)
    result.check_returncode()
    return result.stdout

def start(args):
    log = open(work / (Path(args[0]).name + ".log"), "w")
    logs.append(log)
    child = subprocess.Popen(args, cwd=work, env=env, stdout=subprocess.PIPE, stderr=log, text=True)
    children.append(child)
    print("$ " + " ".join(map(str, args)), flush=True)
    return child

def ready(child):
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ)
        if not selector.select(10):
            raise RuntimeError("startup timeout")
        line = child.stdout.readline().strip()
        if not line:
            raise RuntimeError("process exited during startup")
        print(line, flush=True)
        return line

try:
    for name in ("ca", "proxy", "connector"):
        run(["go", "build", "-buildvcs=false", "-o", str(work/name), "./cmd/"+name])
    shutil.copy(repo/"go.mod", work/"go.mod")
    shutil.copytree(repo/"internal"/"ca", work/"internal"/"ca")
    (work/"cmd"/"fixture").mkdir(parents=True)
    (work/"cmd"/"app").mkdir(parents=True)
    (work/"cmd"/"fixture"/"main.go").write_text('''package main
import("os";"time";"perimeter/internal/ca")
func save(path string,data []byte,mode os.FileMode){if err:=os.WriteFile(path,data,mode);err!=nil{panic(err)}}
func main(){c,err:=ca.Load("ca.crt","ca.key");if err!=nil{panic(err)}
a,k,err:=c.Issue("aisha","finance",10*time.Minute);if err!=nil{panic(err)};save("aisha.crt",a,0644);save("aisha.key",k,0600)
a,k,err=c.IssueConnector("dc-mumbai-1",10*time.Minute);if err!=nil{panic(err)};save("connector.crt",a,0644);save("connector.key",k,0600)}
''')
    (work/"cmd"/"app"/"main.go").write_text('''package main
import("encoding/json";"net";"net/http";"os")
func main(){l,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{panic(err)}
if _,err:=os.Stdout.WriteString(l.Addr().String()+"\\n");err!=nil{panic(err)}
s:=&http.Server{Handler:http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.Header().Set("Content-Type","application/json");if err:=json.NewEncoder(w).Encode(map[string]string{"body":"internal payroll app","path":r.URL.Path,"user":r.Header.Get("X-Perimeter-User"),"group":r.Header.Get("X-Perimeter-Group"),"posture":r.Header.Get("X-Device-Posture")});err!=nil{panic(http.ErrAbortHandler)}})}
if err:=s.Serve(l);err!=nil{panic(err)}}
''')
    for name in ("fixture", "app"):
        run(["go", "build", "-buildvcs=false", "-o", str(work/name), "./cmd/"+name], work)
    run([str(work/"ca")], work)
    run([str(work/"fixture")], work)
    shutil.copy(repo/"policy.json", work/"policy.json")
    shutil.copy(repo/"connectors.json", work/"connectors.json")
    app = start([str(work/"app")])
    app_address = ready(app)
    (work/"connector-apps.json").write_text(json.dumps({"payroll":app_address,"wiki":app_address}))
    proxy = start([str(work/"proxy")])
    ready(proxy)
    connector = start([str(work/"connector")])
    base = ["curl", "--silent", "--show-error", "--max-time", "5", "--cacert", "ca.crt", "--cert", "aisha.crt", "--key", "aisha.key"]
    good = base + ["-H", 'X-Device-Posture: {"disk_encrypted":true,"firewall_on":true}', "-H", "X-Perimeter-User: admin", "-H", "X-Perimeter-Group: admin", "-i", "https://127.0.0.1:8443/apps/payroll/report"]
    for attempt in range(30):
        output = run(good, work)
        if output.splitlines()[0].split()[1] == "200":
            break
        time.sleep(0.1)
    else:
        raise RuntimeError("connector did not become ready")
    assert '"user":"aisha"' in output and '"posture":""' in output and '"path":"/report"' in output
    bad = base + ["-H", 'X-Device-Posture: {"disk_encrypted":false,"firewall_on":true}', "-i", "https://127.0.0.1:8443/apps/payroll/report"]
    output = run(bad, work)
    assert output.splitlines()[0].split()[1] == "403" and output.endswith("denied")
finally:
    for child in reversed(children):
        child.terminate()
    for child in reversed(children):
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)
        child.stdout.close()
    for log in logs:
        log.close()
    print("All demo processes stopped and reaped. Artifacts:", work, flush=True)
