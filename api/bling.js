// Backend seguro Pug Wear -> Bling (função serverless Vercel)
// Guarda o token do Bling no Supabase (tabela protegida) e renova sozinho.
// Usa REST puro do Supabase com a secret key só no header "apikey".
// Ações: oauth (seed), faccoes, faccao, produto, conta-pagar, nfse.

const BLING_API = 'https://api.bling.com.br/Api/v3';
const BLING_WWW = 'https://www.bling.com.br/Api/v3';
const TIPO_FORNECEDOR = 2759122975;
const PORTADOR_CAIXA = 2759123137;
const TAMS = ['P', 'M', 'G', 'GG', 'G1', 'G2'];

const SB_URL = (process.env.SUPABASE_URL || '').trim().replace(/\/+$/, '');
const SB_KEY = (process.env.SUPABASE_SERVICE_KEY || '').trim();

function cors(res, origin) {
  res.setHeader('Access-Control-Allow-Origin', origin || '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-app-secret');
}

function basicAuth() {
  return 'Basic ' + Buffer.from(process.env.BLING_CLIENT_ID + ':' + process.env.BLING_CLIENT_SECRET).toString('base64');
}

// ---- Supabase REST (secret key só no header apikey) ----
async function sbGetToken() {
  const r = await fetch(SB_URL + '/rest/v1/bling_token?id=eq.main&select=*', { headers: { apikey: SB_KEY } });
  const txt = await r.text();
  let arr; try { arr = JSON.parse(txt); } catch (e) { arr = null; }
  return { status: r.status, row: (Array.isArray(arr) && arr[0]) ? arr[0] : null, raw: txt.slice(0, 160) };
}
async function sbSaveToken(obj) {
  const r = await fetch(SB_URL + '/rest/v1/bling_token', {
    method: 'POST',
    headers: { apikey: SB_KEY, 'Content-Type': 'application/json', Prefer: 'resolution=merge-duplicates,return=minimal' },
    body: JSON.stringify({ id: 'main', ...obj })
  });
  return r.status;
}

async function getToken() {
  const g = await sbGetToken();
  if (!g.row || !g.row.refresh_token) {
    const e = new Error('token_nao_configurado');
    e.diag = 'supabase status=' + g.status + ' body=' + g.raw;
    throw e;
  }
  const restante = g.row.expires_at ? (new Date(g.row.expires_at).getTime() - Date.now()) : 0;
  if (g.row.access_token && restante > 120000) return g.row.access_token;
  // renova
  const r = await fetch(BLING_API + '/oauth/token', {
    method: 'POST',
    headers: { 'Authorization': basicAuth(), 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: g.row.refresh_token })
  });
  const j = await r.json();
  if (!j.access_token) { const e = new Error('refresh_falhou'); e.diag = JSON.stringify(j).slice(0, 160); throw e; }
  await sbSaveToken({
    access_token: j.access_token,
    refresh_token: j.refresh_token || g.row.refresh_token,
    expires_at: new Date(Date.now() + (j.expires_in - 60) * 1000).toISOString()
  });
  return j.access_token;
}

async function bfetch(path, token, opts = {}) {
  const r = await fetch(BLING_API + path, {
    ...opts,
    headers: { 'Authorization': 'Bearer ' + token, 'Accept': 'application/json', 'Content-Type': 'application/json', ...(opts.headers || {}) }
  });
  const txt = await r.text();
  let body; try { body = txt ? JSON.parse(txt) : {}; } catch (e) { body = { raw: txt }; }
  return { status: r.status, body };
}

export default async function handler(req, res) {
 try {
  cors(res, req.headers.origin);
  if (req.method === 'OPTIONS') return res.status(204).end();
  const action = (req.query.action || '').toString();

  // ---- Seed do OAuth (uma vez) ----
  if (action === 'oauth') {
    const code = (req.query.code || '').toString();
    if (!code) {
      const redirect = 'https://' + req.headers.host + '/api/bling?action=oauth';
      const u = BLING_WWW + '/oauth/authorize?response_type=code&client_id=' + process.env.BLING_CLIENT_ID +
        '&redirect_uri=' + encodeURIComponent(redirect) + '&state=seed' + Date.now();
      res.writeHead(302, { Location: u });
      return res.end();
    }
    const r = await fetch(BLING_API + '/oauth/token', {
      method: 'POST',
      headers: { 'Authorization': basicAuth(), 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code })
    });
    const j = await r.json();
    if (!j.access_token) return res.status(400).send('<h3>Falha ao conectar</h3><pre>' + JSON.stringify(j, null, 2) + '</pre>');
    await sbSaveToken({
      access_token: j.access_token,
      refresh_token: j.refresh_token,
      expires_at: new Date(Date.now() + (j.expires_in - 60) * 1000).toISOString()
    });
    return res.status(200).send('<h2>Bling conectado com sucesso ✓</h2><p>Pode fechar esta aba e voltar ao app.</p>');
  }

  // ---- diagnóstico rápido (não exige token do Bling) ----
  if (action === 'diag') {
    const info = { envUrl: SB_URL, urlLen: SB_URL.length, keyLen: SB_KEY.length, keyOk: SB_KEY.startsWith('sb_secret_') };
    try {
      const r = await fetch(SB_URL + '/rest/v1/bling_token?id=eq.main&select=id,refresh_token', { headers: { apikey: SB_KEY } });
      info.supabaseStatus = r.status;
      const t = await r.text();
      info.temRefresh = t.includes('refresh_token');
      info.bodyPreview = t.replace(/[A-Za-z0-9_-]{25,}/g, '[...]').slice(0, 160);
    } catch (e) {
      info.fetchErro = String((e && e.cause && e.cause.message) || (e && e.message) || e);
    }
    return res.status(200).json(info);
  }

  // ---- demais ações exigem o segredo do app ----
  if (process.env.APP_SECRET && req.headers['x-app-secret'] !== process.env.APP_SECRET) {
    return res.status(401).json({ erro: 'nao_autorizado' });
  }

  let token;
  try { token = await getToken(); }
  catch (e) { return res.status(500).json({ erro: 'token', detalhe: String(e.message || e), diag: e.diag || null }); }

  try {
    if (action === 'faccoes') {
      const q = (req.query.q || '').toString();
      const { body } = await bfetch('/contatos?limite=100&pagina=1' + (q ? ('&pesquisa=' + encodeURIComponent(q)) : ''), token);
      const lista = (body.data || []).map(c => ({ id: c.id, nome: c.nome, doc: c.numeroDocumento || '' }));
      return res.status(200).json({ faccoes: lista });
    }
    if (action === 'faccao') {
      const id = (req.query.id || '').toString();
      const { body } = await bfetch('/contatos/' + id, token);
      const c = body.data || {};
      const e = (c.endereco && c.endereco.geral) ? c.endereco.geral : (c.endereco || {});
      const endereco = [e.endereco, e.numero, e.bairro, e.municipio && (e.municipio + '/' + (e.uf || '')), e.cep].filter(Boolean).join(', ');
      const fornecedor = (c.tiposContato || []).some(t => t.id === TIPO_FORNECEDOR);
      return res.status(200).json({ id: c.id, nome: c.nome, cnpj: c.numeroDocumento || '', endereco, fornecedor });
    }
    if (action === 'produto') {
      const ref = (req.query.ref || '').toString().trim();
      if (!ref) return res.status(400).json({ erro: 'ref_vazia' });
      // percorre todo o catálogo (a busca do Bling por texto não devolve tudo) e filtra pelo prefixo do código
      const cores = {};
      let nome = '', pagina = 1, continua = true, vistos = 0;
      while (continua && pagina <= 12) {
        const { body } = await bfetch('/produtos?limite=100&pagina=' + pagina, token);
        const arr = body.data || [];
        for (const p of arr) {
          if (!p.codigo || !p.codigo.startsWith(ref + '-')) continue;
          if (p.formato && p.formato !== 'S') continue; // só variações (tamanho)
          const resto = p.codigo.slice(ref.length + 1);
          const partes = resto.split('-');
          const tam = partes[partes.length - 1];
          const cor = partes.slice(0, -1).join('-');
          if (!TAMS.includes(tam) || !cor) continue;
          cores[cor] = cores[cor] || {};
          cores[cor][tam] = 0;
          if (!nome && p.nome) nome = p.nome.split(' - ')[0];
          vistos++;
        }
        continua = arr.length === 100;
        pagina++;
      }
      return res.status(200).json({ ref, produto: nome, cores: Object.keys(cores), gradeVazia: cores, tamanhos: TAMS, variacoes: vistos });
    }
    if (action === 'conta-pagar' && req.method === 'POST') {
      const b = req.body || {};
      const payload = {
        vencimento: b.vencimento,
        valor: Number(b.valor),
        historico: b.historico || 'Fechamento produção (facção)',
        portador: { id: PORTADOR_CAIXA }
      };
      if (b.idContato) payload.contato = { id: Number(b.idContato) };
      const { status, body } = await bfetch('/contas/pagar', token, { method: 'POST', body: JSON.stringify(payload) });
      return res.status(status).json(body);
    }
    if (action === 'nfse') {
      return res.status(501).json({ erro: 'nfse_pendente', detalhe: 'NFS-e depende de config fiscal no Bling (certificado, prefeitura, ISS). Validar com contador.' });
    }
    return res.status(400).json({ erro: 'acao_invalida' });
  } catch (e) {
    return res.status(500).json({ erro: 'falha', detalhe: String(e.message || e) });
  }
 } catch (fatal) {
  try { return res.status(200).json({ crashCapturado: String(fatal && (fatal.stack || fatal.message || fatal)) }); }
  catch (_) { return; }
 }
}
