// Backend seguro Pug Wear -> Bling (função serverless Vercel)
// Guarda o token do Bling no Supabase (tabela protegida) e renova sozinho.
// Usa REST puro do Supabase com a secret key só no header "apikey".
// Ações: oauth (seed), faccoes, faccao, produto, conta-pagar, nfse.

const BLING_API = 'https://api.bling.com.br/Api/v3';
const BLING_WWW = 'https://www.bling.com.br/Api/v3';
const TIPO_FORNECEDOR = 2759122975;
const PORTADOR_CAIXA = 2759123137;
const NAT_REMESSA_IND = 15111528516; // natureza "Remessa para Industrialização"
const TAMS = ['P', 'M', 'G', 'GG', 'G1', 'G2'];

// Refs cujas variações têm EAN-13 interno gerado por nós (gravado no GTIN do Bling e do Olist).
// Pra essas, o código de barras da etiqueta é o EAN (bipa no caixa), calculado do SKU de forma
// determinística (mesmo algoritmo usado ao cadastrar). Demais produtos continuam pelo SKU.
const EAN_REFS = ['C-BP-002','C-BP-001','P-PB-001','P-PB-002','P-PUG','S-CLF-001','S-BF-001','S-BC-001','M-BP-001','M-CM-004','CM-PUGW5','P-TCH-Z-001','P-TCH-B-001','C-CASUAL-TCH','B-PREMIUM','C-TEX-PUG','C-JM','CM-PUG','J-CUMFY','M-CLC-004','C-ALF-MILAO'];
const crypto = require('crypto');
function eanFromSku(sku) {
  const h = crypto.createHash('sha1').update(String(sku)).digest('hex');
  const dec = BigInt('0x' + h).toString();
  const nine = dec.slice(-9).padStart(9, '0');
  const base = '200' + nine;
  let s = 0; for (let i = 0; i < 12; i++) { s += (i % 2 ? 3 : 1) * Number(base[i]); }
  const dv = (10 - (s % 10)) % 10;
  return base + dv;
}

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

  // ---- Proxy simples pro Olist/Tiny (token vem no header, não é guardado) ----
  if (action === 'olist-get') {
    const path = (req.query.path || '').toString();
    const otok = req.headers['x-olist-token'];
    if (!path || !otok) return res.status(400).json({ erro: 'faltando_path_ou_token' });
    try {
      const r = await fetch('https://api.tiny.com.br/public-api/v3' + path, { headers: { Authorization: 'Bearer ' + otok, Accept: 'application/json' } });
      const txt = await r.text();
      let b; try { b = txt ? JSON.parse(txt) : {}; } catch (e) { b = { raw: txt.slice(0, 400) }; }
      return res.status(r.status).json(b);
    } catch (e) { return res.status(502).json({ erro: 'olist_falha', detalhe: String(e.message || e) }); }
  }

  // ---- Proxy de escrita pro Olist/Tiny (POST/PUT) — token no header, não é guardado ----
  if (action === 'olist-post') {
    const path = (req.query.path || '').toString();
    const otok = req.headers['x-olist-token'];
    const metodo = (req.query.metodo || 'POST').toString().toUpperCase();
    if (!path || !otok) return res.status(400).json({ erro: 'faltando_path_ou_token' });
    try {
      const r = await fetch('https://api.tiny.com.br/public-api/v3' + path, {
        method: metodo,
        headers: { Authorization: 'Bearer ' + otok, Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify(req.body || {})
      });
      const txt = await r.text();
      let b; try { b = txt ? JSON.parse(txt) : {}; } catch (e) { b = { raw: txt.slice(0, 600) }; }
      return res.status(r.status).json(b);
    } catch (e) { return res.status(502).json({ erro: 'olist_falha', detalhe: String(e.message || e) }); }
  }

  // ---- Renova o token do Olist/Tiny via refresh_token (o navegador/sandbox é bloqueado; o Vercel consegue) ----
  if (action === 'olist-refresh') {
    const rt = req.headers['x-olist-refresh'] || (req.body && req.body.refresh_token);
    if (!rt) return res.status(400).json({ erro: 'faltando_refresh' });
    const cid = process.env.OLIST_CLIENT_ID || 'tiny-api-7c08bd5379d7776c3177153e925dd6a946b13ccd-1784241734';
    const sec = process.env.OLIST_CLIENT_SECRET || 'JUnS3F1UWGEpsXJfzQwx3LM1CtPpeUvi';
    const body = new URLSearchParams();
    body.set('grant_type', 'refresh_token'); body.set('client_id', cid); body.set('client_secret', sec); body.set('refresh_token', rt);
    try {
      const r = await fetch('https://accounts.tiny.com.br/realms/tiny/protocol/openid-connect/token', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: body.toString()
      });
      const txt = await r.text(); let b; try { b = JSON.parse(txt); } catch (e) { b = { raw: txt.slice(0, 300) }; }
      return res.status(r.status).json(b);
    } catch (e) { return res.status(502).json({ erro: 'olist_refresh_falha', detalhe: String(e.message || e) }); }
  }

  // ---- Troca authorization_code por tokens do Olist (Vercel nao e bloqueado) ----
  if (action === 'olist-auth') {
    const code = (req.body && req.body.code) || req.query.code;
    const redirect = (req.body && req.body.redirect_uri) || 'https://oauth.pstmn.io/v1/callback';
    if (!code) return res.status(400).json({ erro: 'faltando_code' });
    const cid = process.env.OLIST_CLIENT_ID || 'tiny-api-7c08bd5379d7776c3177153e925dd6a946b13ccd-1784241734';
    const sec = process.env.OLIST_CLIENT_SECRET || 'JUnS3F1UWGEpsXJfzQwx3LM1CtPpeUvi';
    const body = new URLSearchParams();
    body.set('grant_type', 'authorization_code'); body.set('client_id', cid); body.set('client_secret', sec); body.set('code', code); body.set('redirect_uri', redirect);
    try {
      const r = await fetch('https://accounts.tiny.com.br/realms/tiny/protocol/openid-connect/token', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: body.toString()
      });
      const txt = await r.text(); let b; try { b = JSON.parse(txt); } catch (e) { b = { raw: txt.slice(0, 300) }; }
      return res.status(r.status).json(b);
    } catch (e) { return res.status(502).json({ erro: 'olist_auth_falha', detalhe: String(e.message || e) }); }
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
    // ---- Lista TODOS os fornecedores (facções) — não depende da busca por texto ----
    if (action === 'fornecedores') {
      const lista = [];
      let pagina = 1, continua = true;
      while (continua && pagina <= 6) {
        const { body } = await bfetch('/contatos?idTipoContato=' + TIPO_FORNECEDOR + '&limite=100&pagina=' + pagina, token);
        const arr = body.data || [];
        arr.forEach(c => lista.push({ id: c.id, nome: c.nome, doc: c.numeroDocumento || '' }));
        continua = arr.length === 100;
        pagina++;
      }
      // ordena por nome
      lista.sort((a, b) => (a.nome || '').localeCompare(b.nome || ''));
      return res.status(200).json({ fornecedores: lista, total: lista.length });
    }
    if (action === 'faccao') {
      const id = (req.query.id || '').toString();
      const { body } = await bfetch('/contatos/' + id, token);
      const c = body.data || {};
      const e = (c.endereco && c.endereco.geral) ? c.endereco.geral : (c.endereco || {});
      const endereco = [e.endereco, e.numero, e.bairro, e.municipio && (e.municipio + '/' + (e.uf || '')), e.cep].filter(Boolean).join(', ');
      const fornecedor = (c.tiposContato || []).some(t => t.id === TIPO_FORNECEDOR);
      return res.status(200).json({ id: c.id, nome: c.nome, cnpj: c.numeroDocumento || '', endereco, fornecedor, ie: c.ie || '', indicadorIe: c.indicadorIe });
    }
    if (action === 'catalogo') {
      // lista codigo+gtin+nome+formato de todo o catálogo, filtrando por prefixo(s) opcional(is)
      const pref = (req.query.pref || '').toString().trim().toUpperCase();
      const prefs = pref ? pref.split(',').map(s => s.trim()).filter(Boolean) : [];
      const out = [];
      let pagina = 1, continua = true, tent = 0;
      while (continua && pagina <= 80) {
        const { status, body } = await bfetch('/produtos?limite=100&pagina=' + pagina + '&criterio=2', token);
        if (status === 429 || status >= 500) { if (++tent > 6) break; await new Promise(r => setTimeout(r, 700)); continue; }
        tent = 0;
        const arr = body.data || [];
        for (const p of arr) {
          const cod = (p.codigo || '').toString();
          if (prefs.length && !prefs.some(pf => cod.toUpperCase().startsWith(pf))) continue;
          out.push({ id: p.id, codigo: cod, nome: p.nome || '', gtin: (p.gtin || '').toString(), formato: p.formato || '', preco: Number(p.preco) || 0, situacao: p.situacao || '' });
        }
        continua = arr.length === 100;
        pagina++;
        await new Promise(r => setTimeout(r, 300));
      }
      return res.status(200).json({ n: out.length, itens: out });
    }
    if (action === 'bling-raw') {
      // proxy autenticado genérico pro Bling (criar/editar produtos, custo, etc.)
      const path = (req.query.path || '').toString();
      const metodo = (req.query.metodo || 'GET').toString().toUpperCase();
      if (!path) return res.status(400).json({ erro: 'faltando_path' });
      const opts = (metodo === 'GET') ? {} : { method: metodo, body: JSON.stringify(req.body || {}) };
      const { status, body } = await bfetch(path, token, opts);
      return res.status(status).json(body);
    }
    if (action === 'produto') {
      const ref = (req.query.ref || '').toString().trim();
      if (!ref) return res.status(400).json({ erro: 'ref_vazia' });
      // percorre todo o catálogo (a busca do Bling por texto não devolve tudo) e filtra pelo prefixo do código
      const cores = {};
      const codigos = {}; // cor -> tam -> código REAL do Bling (SKU exato, sem remontar)
      const gtins = {};   // cor -> tam -> GTIN/EAN do Bling (pra código de barras)
      const precos = {};  // cor -> tam -> preço do Bling
      let nome = '', pagina = 1, continua = true, vistos = 0, tent = 0;
      const SZALL = /^(P|M|G|GG|G1|G2|G3|3[0-9]|4[0-9]|50)$/; // letra OU numérico (36-50)
      const tamsFound = {};
      while (continua && pagina <= 80) {
        const { status, body } = await bfetch('/produtos?limite=100&pagina=' + pagina + '&criterio=2', token);
        if (status === 429 || status >= 500) { if (++tent > 6) break; await new Promise(r => setTimeout(r, 700)); continue; }
        tent = 0;
        const arr = body.data || [];
        for (const p of arr) {
          if (!p.codigo || !p.codigo.startsWith(ref + '-')) continue;
          if (p.formato && p.formato !== 'S') continue; // só variações (tamanho)
          const resto = p.codigo.slice(ref.length + 1);
          const partes = resto.split('-');
          const tam = partes[partes.length - 1];
          let cor = partes.slice(0, -1).join('-');
          if (!SZALL.test(tam)) continue;
          if (!cor) cor = 'Única'; // produtos de tamanho único sem cor (ex: Calça Jeans)
          tamsFound[tam] = true;
          cores[cor] = cores[cor] || {};
          cores[cor][tam] = 0;
          codigos[cor] = codigos[cor] || {};
          codigos[cor][tam] = p.codigo; // código exato como está no Bling
          gtins[cor] = gtins[cor] || {};
          // sempre usa o EAN-13 determinístico do código — padroniza TODOS os produtos em EAN-13
          gtins[cor][tam] = eanFromSku(p.codigo);
          precos[cor] = precos[cor] || {};
          precos[cor][tam] = Number(p.preco) || 0;
          if (!nome && p.nome) nome = p.nome.split(' - ')[0];
          vistos++;
        }
        continua = arr.length === 100;
        pagina++;
        await new Promise(r => setTimeout(r, 300));
      }
      // preço mais comum como padrão do produto
      let precoPadrao = 0; const cont = {};
      Object.values(precos).forEach(o => Object.values(o).forEach(v => { if (v > 0) { cont[v] = (cont[v] || 0) + 1; } }));
      let melhor = 0; Object.keys(cont).forEach(v => { if (cont[v] > melhor) { melhor = cont[v]; precoPadrao = Number(v); } });
      // monta a lista de tamanhos encontrados: letras na ordem padrão, depois numéricos crescente
      const ordLet = ['P', 'M', 'G', 'GG', 'G1', 'G2', 'G3'];
      const found = Object.keys(tamsFound);
      const lets = ordLet.filter(t => found.includes(t));
      const nums = found.filter(t => /^\d+$/.test(t)).sort((a, b) => Number(a) - Number(b));
      const tamanhos = lets.concat(nums).length ? lets.concat(nums) : TAMS;
      return res.status(200).json({ ref, produto: nome, cores: Object.keys(cores), gradeVazia: cores, codigos: codigos, gtins: gtins, precos: precos, precoPadrao: precoPadrao, tamanhos: tamanhos, variacoes: vistos });
    }
    if (action === 'conta-pagar' && req.method === 'POST') {
      const b = req.body || {};
      const hoje = new Date().toISOString().slice(0, 10);
      const payload = {
        vencimento: b.vencimento,
        valor: Number(b.valor),
        dataEmissao: b.dataEmissao || hoje,
        competencia: b.competencia || b.dataEmissao || hoje,
        historico: b.historico || 'Fechamento produção (facção)',
        portador: { id: PORTADOR_CAIXA }
      };
      if (b.numeroDocumento) payload.numeroDocumento = String(b.numeroDocumento);
      if (b.idContato) payload.contato = { id: Number(b.idContato) };
      const { status, body } = await bfetch('/contas/pagar', token, { method: 'POST', body: JSON.stringify(payload) });
      return res.status(status).json(body);
    }
    // ---- Emitir NF-e de remessa para industrialização (cria rascunho no Bling) ----
    // ---- Lista itens de "facção" (remessa industrialização): codigo/nome contendo FAC ----
    if (action === 'fac-itens' && req.method === 'GET') {
      const found = {};
      for (let pg = 1; pg <= 12; pg++) {
        const r = await bfetch('/produtos?limite=100&pagina=' + pg, token);
        const arr = ((r.body || {}).data) || [];
        arr.forEach(p => {
          const n = (p.nome || '').toLowerCase(), c = (p.codigo || '').toLowerCase();
          if (/(^|[-_ ])fac([-_ ]|$)/.test(c) || /facc|facç/.test(n)) found[p.id] = { id: p.id, codigo: p.codigo, nome: p.nome, situacao: p.situacao };
        });
        if (arr.length < 100) break;
      }
      const itens = Object.values(found).filter(it => it.situacao !== 'I');
      for (const it of itens) {
        try { const d = ((await bfetch('/produtos/' + it.id, token)).body || {}).data || {}; it.ncm = (d.tributacao && d.tributacao.ncm) || ''; } catch (e) { it.ncm = ''; }
      }
      return res.status(200).json({ itens });
    }
    if (action === 'nfe-remessa' && req.method === 'POST') {
      const b = req.body || {};
      if (!b.idContato) return res.status(400).json({ erro: 'sem_faccao' });
      const qtd = Number(b.quantidade) || 0;
      const valor = Number(b.valor) || 16.50;
      if (qtd <= 0) return res.status(400).json({ erro: 'qtd_invalida' });
      const agora = new Date().toISOString().slice(0, 19).replace('T', ' ');
      // busca dados completos do contato (senão o destinatário sai sem nome/endereço)
      const cd = ((await bfetch('/contatos/' + Number(b.idContato), token)).body || {}).data || {};
      const eg = (cd.endereco && cd.endereco.geral) ? cd.endereco.geral : (cd.endereco || {});
      const temIe = !!(cd.ie && String(cd.ie).replace(/\D/g, ''));
      const indIe = cd.indicadorIe || (temIe ? 1 : 9); // 1=contribuinte, 9=não contribuinte
      const naoContrib = indIe === 9 || !temIe;
      const contatoNfe = {
        id: cd.id || Number(b.idContato),
        nome: cd.nome || '',
        numeroDocumento: cd.numeroDocumento || '',
        ie: cd.ie || '',
        indicadorIe: indIe,
        telefone: cd.telefone || cd.celular || '',
        email: cd.email || '',
        endereco: {
          endereco: eg.endereco || '', numero: eg.numero || '', complemento: eg.complemento || '',
          bairro: eg.bairro || '', cep: String(eg.cep || '').replace(/\D/g, ''), municipio: eg.municipio || '', uf: eg.uf || ''
        }
      };
      const payload = {
        tipo: 1,
        serie: 2,
        dataEmissao: agora,
        dataOperacao: agora,
        finalidade: 1,
        consumidorFinal: naoContrib ? 1 : 0,
        indicadorPresenca: naoContrib ? 9 : 0,
        contato: contatoNfe,
        naturezaOperacao: { id: NAT_REMESSA_IND },
        itens: [{
          codigo: b.itemCodigo || 'B-FAC',
          descricao: b.itemDescricao || 'Basica Faccao', unidade: 'Un',
          quantidade: qtd, valor: valor, tipo: 'P',
          classificacaoFiscal: (b.itemNcm ? String(b.itemNcm).replace(/\D/g, '') : '') || '61099000',
          cfop: b.itemCfop || '5901', origem: 0
        }]
      };
      if (b.obs) payload.observacoes = b.obs;
      const { status, body } = await bfetch('/nfe', token, { method: 'POST', body: JSON.stringify(payload) });
      return res.status(status).json(body);
    }
    // ---- Enviar NF-e pra SEFAZ (autorizar) + devolver links da DANFE ----
    if (action === 'nfe-enviar' && req.method === 'POST') {
      const id = (req.body && req.body.id) || '';
      if (!id) return res.status(400).json({ erro: 'sem_id' });
      const env = await bfetch('/nfe/' + id + '/enviar', token, { method: 'POST' });
      // aguarda a autorização da SEFAZ (poll até uns 6s)
      let d = {};
      for (let i = 0; i < 4; i++) {
        await new Promise(r => setTimeout(r, 1500));
        const det = await bfetch('/nfe/' + id, token);
        d = (det.body && det.body.data) || {};
        if (d.linkDanfe || d.linkPDF || [5, 6, 7].includes(d.situacao)) break;
      }
      return res.status(env.status).json({ enviar: env.body, situacao: d.situacao, linkDanfe: d.linkDanfe, linkPDF: d.linkPDF, chaveAcesso: d.chaveAcesso });
    }
    // ---- Buscar o link da DANFE de uma NF-e já emitida (pra reimprimir depois) ----
    if (action === 'nfe-danfe') {
      const id = (req.query.id || (req.body && req.body.id) || '').toString();
      if (!id) return res.status(400).json({ erro: 'sem_id' });
      const det = await bfetch('/nfe/' + id, token);
      const d = (det.body && det.body.data) || {};
      return res.status(200).json({ linkDanfe: d.linkDanfe, linkPDF: d.linkPDF, numero: d.numero, situacao: d.situacao, chaveAcesso: d.chaveAcesso });
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
