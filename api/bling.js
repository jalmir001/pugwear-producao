// Backend seguro Pug Wear -> Bling (função serverless Vercel)
// Guarda o token do Bling no Supabase (tabela protegida) e renova sozinho.
// Ações: oauth (seed), faccoes, faccao, produto, conta-pagar.
import { createClient } from '@supabase/supabase-js';

const BLING_API = 'https://api.bling.com.br/Api/v3';
const BLING_WWW = 'https://www.bling.com.br/Api/v3';
const TIPO_FORNECEDOR = 2759122975;
const PORTADOR_CAIXA = 2759123137;
const TAMS = ['P', 'M', 'G', 'GG', 'G1', 'G2'];

function cors(res, origin) {
  // Em produção, restringir ao domínio do app. '*' aqui é combinado com o x-app-secret.
  res.setHeader('Access-Control-Allow-Origin', origin || '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-app-secret');
}

function db() {
  return createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY, { auth: { persistSession: false } });
}

function basicAuth() {
  return 'Basic ' + Buffer.from(process.env.BLING_CLIENT_ID + ':' + process.env.BLING_CLIENT_SECRET).toString('base64');
}

async function getToken() {
  const sb = db();
  const { data } = await sb.from('bling_token').select('*').eq('id', 'main').maybeSingle();
  if (!data || !data.refresh_token) throw new Error('token_nao_configurado');
  const restante = data.expires_at ? (new Date(data.expires_at).getTime() - Date.now()) : 0;
  if (data.access_token && restante > 120000) return data.access_token;
  // renova
  const r = await fetch(BLING_API + '/oauth/token', {
    method: 'POST',
    headers: { 'Authorization': basicAuth(), 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: data.refresh_token })
  });
  const j = await r.json();
  if (!j.access_token) throw new Error('refresh_falhou: ' + JSON.stringify(j));
  await sb.from('bling_token').update({
    access_token: j.access_token,
    refresh_token: j.refresh_token || data.refresh_token,
    expires_at: new Date(Date.now() + (j.expires_in - 60) * 1000).toISOString()
  }).eq('id', 'main');
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
  cors(res, req.headers.origin);
  if (req.method === 'OPTIONS') return res.status(204).end();
  const action = (req.query.action || '').toString();

  // ---- Seed do OAuth (uma vez): abrir /api/bling?action=oauth no navegador logado no Bling ----
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
    await db().from('bling_token').upsert({
      id: 'main',
      access_token: j.access_token,
      refresh_token: j.refresh_token,
      expires_at: new Date(Date.now() + (j.expires_in - 60) * 1000).toISOString()
    });
    return res.status(200).send('<h2>Bling conectado com sucesso ✓</h2><p>Pode fechar esta aba e voltar ao app.</p>');
  }

  // ---- demais ações exigem o segredo do app ----
  if (process.env.APP_SECRET && req.headers['x-app-secret'] !== process.env.APP_SECRET) {
    return res.status(401).json({ erro: 'nao_autorizado' });
  }

  let token;
  try { token = await getToken(); }
  catch (e) { return res.status(500).json({ erro: 'token', detalhe: String(e.message || e) }); }

  try {
    // ---- Facções: busca contatos por nome (o usuário escolhe) ----
    if (action === 'faccoes') {
      const q = (req.query.q || '').toString();
      const { body } = await bfetch('/contatos?limite=100&pagina=1' + (q ? ('&pesquisa=' + encodeURIComponent(q)) : ''), token);
      const lista = (body.data || []).map(c => ({ id: c.id, nome: c.nome, doc: c.numeroDocumento || '' }));
      return res.status(200).json({ faccoes: lista });
    }

    // ---- Detalhe de uma facção: CNPJ + endereço + se é fornecedor ----
    if (action === 'faccao') {
      const id = (req.query.id || '').toString();
      const { body } = await bfetch('/contatos/' + id, token);
      const c = body.data || {};
      const e = (c.endereco && c.endereco.geral) ? c.endereco.geral : (c.endereco || {});
      const endereco = [e.endereco, e.numero, e.bairro, e.municipio && (e.municipio + '/' + (e.uf || '')), e.cep].filter(Boolean).join(', ');
      const fornecedor = (c.tiposContato || []).some(t => t.id === TIPO_FORNECEDOR);
      return res.status(200).json({ id: c.id, nome: c.nome, cnpj: c.numeroDocumento || '', endereco, fornecedor });
    }

    // ---- Catálogo: monta a grade de cores a partir da referência (ex.: C-BP-001) ----
    if (action === 'produto') {
      const ref = (req.query.ref || '').toString().trim();
      if (!ref) return res.status(400).json({ erro: 'ref_vazia' });
      const cores = {};
      let nome = '', pagina = 1, continua = true;
      while (continua && pagina <= 8) {
        const { body } = await bfetch('/produtos?limite=100&pagina=' + pagina + '&pesquisa=' + encodeURIComponent(ref), token);
        const arr = body.data || [];
        for (const p of arr) {
          if (p.formato !== 'S' || !p.codigo || !p.codigo.startsWith(ref + '-')) continue;
          const resto = p.codigo.slice(ref.length + 1);      // "Cor-Tam"
          const partes = resto.split('-');
          const tam = partes[partes.length - 1];
          const cor = partes.slice(0, -1).join('-');
          if (!TAMS.includes(tam) || !cor) continue;
          cores[cor] = cores[cor] || {};
          cores[cor][tam] = 0;
          if (!nome && p.nome) nome = p.nome.split(' - ')[0];
        }
        continua = arr.length === 100;
        pagina++;
      }
      return res.status(200).json({ ref, produto: nome, cores: Object.keys(cores), gradeVazia: cores, tamanhos: TAMS });
    }

    // ---- Fechamento -> conta a pagar no Bling ----
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

    // ---- NFS-e (NF-e de serviço): PENDENTE de config fiscal (certificado + prefeitura + ISS) ----
    if (action === 'nfse') {
      return res.status(501).json({ erro: 'nfse_pendente', detalhe: 'NFS-e depende de config fiscal no Bling (certificado digital, prefeitura, código de serviço/ISS). Validar com contador antes de emitir.' });
    }

    return res.status(400).json({ erro: 'acao_invalida' });
  } catch (e) {
    return res.status(500).json({ erro: 'falha', detalhe: String(e.message || e) });
  }
}
