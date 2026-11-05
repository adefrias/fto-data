// Provides the small `window.claude` interface the app expects, backed by api.php.
(function () {
  var API = new URL('api.php', document.currentScript.src).href, POLL = 4000;
  var vers = {}, subs = {}, timer = null, inflight = false, first = {};
  function err(m, code) { var e = new Error(m); e.code = code || 'unavailable'; return e; }
  function post(body) {
    return fetch(API, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'onboard' }, body: JSON.stringify(body) })
      .then(function (r) { return r.json().catch(function () { return {}; }).then(function (j) { if (r.status === 401 && j.error === 'auth') { location.reload(); throw err('Signed out.', 'unauthenticated'); } if (!r.ok) throw err(j.error || 'Save failed (' + r.status + ')', r.status >= 500 ? 'unavailable' : r.status === 403 ? 'permission_denied' : 'bad_request'); return j; }); },
        function () { throw err('Could not reach the server.'); });
  }
  function snap(docs) {
    var d = docs.map(function (x) { return { id: x.id, exists: true, metadata: {}, data: function () { return JSON.parse(JSON.stringify(x.data)); } }; });
    return { docs: d, size: d.length, empty: !d.length, metadata: { fromCache: false, hasPendingWrites: false }, docChanges: function () { return []; } };
  }
  function poll() {
    clearTimeout(timer);
    var cols = Object.keys(subs);
    if (!cols.length || inflight) return;
    inflight = true;
    var q = cols.map(function (c) { return c + ':' + (c in vers ? vers[c] : -1); }).join(',');
    fetch(API + '?v=' + encodeURIComponent(q), { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { if (r.status === 401) { location.reload(); throw err('Signed out.', 'unauthenticated'); } if (!r.ok) throw err('Server error ' + r.status); return r.json(); })
      .then(function (j) {
        Object.keys(j.cols || {}).forEach(function (c) { vers[c] = j.cols[c].v; first[c] = true; var s = snap(j.cols[c].docs); (subs[c] || []).forEach(function (x) { x.fn(s); }); });
      })
      .catch(function (e) { cols.forEach(function (c) { if (!first[c]) (subs[c] || []).forEach(function (x) { x.er && x.er(e); }); }); })
      .then(function () { inflight = false; timer = setTimeout(poll, document.hidden ? 15000 : POLL); });
  }
  document.addEventListener('visibilitychange', function () { if (!document.hidden) poll(); });
  function ref(c, id) {
    return {
      set: function (d) { return post({ op: 'set', c: c, id: id, data: d }).then(function () { poll(); }); },
      delete: function () { return post({ op: 'delete', c: c, id: id }).then(function () { poll(); }); },
      acquire: function (o) { return post({ op: 'acquire', k: c + '/' + id, holder: o.holder, ttlMs: o.ttlMs }); }
    };
  }
  function get(c) { return fetch(API + '?v=' + encodeURIComponent(c + ':-1'), { credentials: 'same-origin', cache: 'no-store' }).then(function (r) { return r.json(); }).then(function (j) { return snap(j.cols[c].docs); }); }
  var db = {
    doc: function (p) { var a = p.split('/'); return ref(a[0], a[1]); },
    collection: function (c) {
      return {
        doc: function (id) { return ref(c, id); },
        get: function () { return get(c); },
        limit: function () { return { get: function () { return get(c); } }; },
        onSnapshot: function (fn, er) { var o = { fn: fn, er: er }; (subs[c] = subs[c] || []).push(o); clearTimeout(timer); timer = setTimeout(poll, 0); return function () { subs[c] = subs[c].filter(function (x) { return x !== o; }); }; }
      };
    }
  };
  var user = { can: function () { return Promise.resolve(true); }, canEdit: function () { return Promise.resolve(true); } };
  var downloads = {
    save: function (o) {
      return new Promise(function (res) {
        var b = new Blob([o.data], { type: /\.json$/i.test(o.filename) ? 'application/json' : 'text/csv;charset=utf-8' }), a = document.createElement('a');
        a.href = URL.createObjectURL(b); a.download = o.filename; document.body.appendChild(a); a.click();
        setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500); res({ status: 'saved' });
      });
    }
  };
  var auth = {
    me: function () { return fetch(API + '?a=me', { credentials: 'same-origin', cache: 'no-store' }).then(function (r) { if (!r.ok) throw err('Server error ' + r.status); return r.json(); }, function () { throw err('Could not reach the server.'); }); },
    login: function (email, pw) { return post({ op: 'login', email: email, pw: pw }); },
    logout: function () { return post({ op: 'logout' }); },
    changePassword: function (o, n) { return post({ op: 'password', old: o, new: n }); },
    setup: function (o) { return post({ op: 'setup', name: o.name, email: o.email, pw: o.pw, starter: o.starter }); }
  };
  window.claude = { use: function (n) { return Promise.resolve(n === 'db' ? db : n === 'user' ? user : n === 'downloads' ? downloads : n === 'auth' ? auth : null); } };
})();
