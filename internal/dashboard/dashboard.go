// Package dashboard serves a live, local web view of captured requests at
// /_dashboard, streaming new records over Server-Sent Events (/_events).
package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"gocatcher/internal/capture"
)

// Register mounts the dashboard routes on mux. If token is non-empty, requests
// must present it via ?token= or an Authorization: Bearer header.
func Register(mux *http.ServeMux, store *capture.Store, token string) {
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if token != "" && !authorized(r, token) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}

	mux.HandleFunc("GET /_dashboard", auth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, page)
	}))

	mux.HandleFunc("GET /_history", auth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(store.All())
	}))

	mux.HandleFunc("GET /_events", auth(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "stream unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		ch, cancel := store.Subscribe()
		defer cancel()
		// Backfill current ring.
		for _, rec := range store.All() {
			writeSSE(w, rec)
		}
		flusher.Flush()
		for {
			select {
			case <-r.Context().Done():
				return
			case rec, ok := <-ch:
				if !ok {
					return
				}
				writeSSE(w, rec)
				flusher.Flush()
			}
		}
	}))
}

func authorized(r *http.Request, token string) bool {
	if r.URL.Query().Get("token") == token {
		return true
	}
	h := r.Header.Get("Authorization")
	return strings.TrimPrefix(h, "Bearer ") == token && h != ""
}

func writeSSE(w http.ResponseWriter, rec capture.Record) {
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", b)
}

const page = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GoCatcher — live</title>
<style>
  :root{--bg:#05161c;--panel:#0a222c;--cyan:#4fd0e1;--amber:#ffb000;--green:#5ae696;--dim:#5a7f8e;--text:#d6f0f5}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
  header{display:flex;align-items:center;gap:12px;padding:14px 18px;border-bottom:1px solid #0e3a49;position:sticky;top:0;background:var(--bg)}
  header h1{font-size:16px;margin:0;letter-spacing:2px;color:var(--cyan)}
  .led{width:9px;height:9px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green)}
  .count{margin-left:auto;color:var(--dim)}
  input{background:var(--panel);border:1px solid #0e3a49;color:var(--text);padding:6px 10px;border-radius:6px;font:inherit}
  main{padding:14px 18px}
  .row{border:1px solid #0e3a49;background:var(--panel);border-radius:8px;padding:10px 12px;margin-bottom:8px}
  .row.alert{border-color:var(--amber);box-shadow:0 0 0 1px var(--amber) inset}
  .meta{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
  .m{color:var(--amber)} .p{color:var(--cyan)} .ip{color:var(--dim)} .t{color:var(--dim);margin-left:auto}
  .tag{background:var(--amber);color:#05161c;padding:1px 7px;border-radius:10px;font-weight:700;font-size:12px}
  pre{margin:8px 0 0;white-space:pre-wrap;color:var(--green);font-size:13px}
  .hdr{color:var(--dim);font-size:12px;margin-top:6px}
</style></head>
<body>
<header>
  <span class="led"></span><h1>GOCATCHER · LIVE</h1>
  <input id="f" placeholder="filter path/ip/method…" oninput="render()">
  <span class="count" id="count">0 requests</span>
</header>
<main id="list"></main>
<script>
const rows=[]; const seen=new Set();
function esc(s){return (s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
function render(){
  const q=(document.getElementById('f').value||'').toLowerCase();
  const list=document.getElementById('list'); list.innerHTML='';
  let n=0;
  for(const r of rows.slice().reverse()){
    const hay=(r.method+' '+r.path+' '+r.remote+' '+(r.alert||'')).toLowerCase();
    if(q && !hay.includes(q)) continue;
    n++;
    const d=document.createElement('div'); d.className='row'+(r.alert?' alert':'');
    let h='<div class="meta">';
    if(r.alert) h+='<span class="tag">'+esc(r.alert)+'</span>';
    h+='<span class="m">'+esc(r.method||r.proto)+'</span><span class="p">'+esc(r.path)+(r.query?('?'+esc(r.query)):'')+'</span>';
    h+='<span class="ip">'+esc(r.remote)+'</span><span class="t">'+new Date(r.time).toLocaleTimeString()+'</span></div>';
    if(r.token) h+='<div class="hdr">token: '+esc(r.token)+'</div>';
    if(r.decoded) h+='<pre>'+esc(r.decoded)+'</pre>';
    d.innerHTML=h; list.appendChild(d);
  }
  document.getElementById('count').textContent=n+' requests';
}
const tok=new URLSearchParams(location.search).get('token');
const es=new EventSource('/_events'+(tok?('?token='+encodeURIComponent(tok)):''));
es.onmessage=e=>{const r=JSON.parse(e.data); if(seen.has(r.seq))return; seen.add(r.seq); rows.push(r); render();};
</script>
</body></html>`
