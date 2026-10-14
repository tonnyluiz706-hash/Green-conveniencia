/* ============================================================
 * Green Conveniência — Backend completo (single-file)
 *
 * Rotas ADMIN:
 *   POST   /api/setup           → cria o primeiro admin (só 1x)
 *   POST   /api/login           → login admin
 *   POST   /api/logout          → logout admin
 *   GET    /api/me              → admin logado
 *   GET    /api/produtos        → lista produtos ativos (público)
 *   GET    /api/admin/produtos  → lista TODOS os produtos (auth)
 *   POST   /api/produtos        → cria produto (auth)
 *   PUT    /api/produto         → edita produto (auth)
 *   DELETE /api/produto?id=X    → deleta produto (auth)
 *   POST   /api/upload          → upload de imagem (auth)
 *
 * Rotas CLIENTE:
 *   POST   /api/cliente/cadastro → cria cliente novo
 *   POST   /api/cliente/login    → login do cliente
 *   POST   /api/cliente/logout   → encerra sessão cliente
 *   GET    /api/cliente/me       → dados do cliente logado
 * ============================================================ */

const SESSAO_DURACAO_HORAS = 24 * 7;

/* ---------- CORS ---------- */
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

/* ---------- Helpers ---------- */
const json = (data, status = 200) =>
  Response.json(data, { status, headers: CORS });

const erro = (msg, status = 400) =>
  Response.json({ erro: msg }, { status, headers: CORS });

const buf2hex = buf =>
  [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');

function gerarToken(){
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return buf2hex(b);
}

function gerarSalt(){
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return buf2hex(b);
}

async function hashSenha(senha, salt){
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(senha), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name:'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash:'SHA-256' },
    key, 256
  );
  return buf2hex(bits);
}

async function autenticar(request, env){
  const auth  = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return null;

  return await env.DB.prepare(
    `SELECT s.usuario_id, u.email
       FROM sessoes s
       JOIN usuarios u ON u.id = s.usuario_id
      WHERE s.token = ? AND s.expira_em > datetime('now')`
  ).bind(token).first();
}

async function autenticarCliente(request, env){
  const auth  = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return null;

  return await env.DB.prepare(
    `SELECT c.id, c.nome, c.email, c.foto_url
       FROM sessoes_cliente s
       JOIN clientes c ON c.id = s.cliente_id
      WHERE s.token = ? AND s.expira_em > datetime('now')`
  ).bind(token).first();
}

/* ============================================================
 * ROTEADOR
 * ============================================================ */
export async function onRequest(context){
  const { request, env } = context;
  const url    = new URL(request.url);
  const rota   = url.pathname.replace('/api/', '').replace(/\/$/, '');
  const metodo = request.method;

  if (metodo === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }

  try {
    // Admin
    if (rota === 'setup'           && metodo === 'POST')   return setup(context);
    if (rota === 'login'           && metodo === 'POST')   return login(context);
    if (rota === 'logout'          && metodo === 'POST')   return logout(context);
    if (rota === 'me'              && metodo === 'GET')    return me(context);
    if (rota === 'produtos'        && metodo === 'GET')    return listarProdutos(context);
    if (rota === 'admin/produtos'  && metodo === 'GET')    return listarTodosProdutos(context);
    if (rota === 'produtos'        && metodo === 'POST')   return criarProduto(context);
    if (rota === 'produto'         && metodo === 'PUT')    return editarProduto(context);
    if (rota === 'produto'         && metodo === 'DELETE') return deletarProduto(context);
    if (rota === 'upload'          && metodo === 'POST')   return uploadImagem(context);

    // Cliente
    if (rota === 'cliente/cadastro' && metodo === 'POST')  return cadastrarCliente(context);
    if (rota === 'cliente/login'    && metodo === 'POST')  return loginCliente(context);
    if (rota === 'cliente/logout'   && metodo === 'POST')  return logoutCliente(context);
    if (rota === 'cliente/me'       && metodo === 'GET')   return meCliente(context);

    return erro('Rota não encontrada: ' + rota, 404);
  } catch (e){
    console.error('[api] erro:', e);
    return erro('Erro interno: ' + e.message, 500);
  }
}

/* ============================================================
 * SETUP — cria o primeiro admin
 * ============================================================ */
async function setup({ request, env }){
  const total = await env.DB.prepare('SELECT COUNT(*) AS n FROM usuarios').first();
  if (total.n > 0) return erro('Setup já foi feito. Faça login normalmente.', 403);

  const { email, senha } = await request.json();
  if (!email || !senha) return erro('Email e senha obrigatórios');
  if (senha.length < 6) return erro('Senha precisa ter ao menos 6 caracteres');

  const salt = gerarSalt();
  const senha_hash = await hashSenha(senha, salt);

  await env.DB.prepare(
    'INSERT INTO usuarios (email, senha_hash, salt) VALUES (?, ?, ?)'
  ).bind(email, senha_hash, salt).run();

  return json({ ok: true, msg: 'Admin criado! Agora faça login em /api/login' });
}

/* ============================================================
 * LOGIN ADMIN
 * ============================================================ */
async function login({ request, env }){
  const { email, senha } = await request.json();
  if (!email || !senha) return erro('Email e senha obrigatórios');

  const user = await env.DB.prepare(
    'SELECT * FROM usuarios WHERE email = ?'
  ).bind(email).first();
  if (!user) return erro('Email ou senha inválidos', 401);

  const tentativa = await hashSenha(senha, user.salt);
  if (tentativa !== user.senha_hash) return erro('Email ou senha inválidos', 401);

  const token = gerarToken();
  const expira_em = new Date(Date.now() + SESSAO_DURACAO_HORAS * 3600 * 1000)
    .toISOString().slice(0, 19).replace('T', ' ');

  await env.DB.prepare(
    'INSERT INTO sessoes (token, usuario_id, expira_em) VALUES (?, ?, ?)'
  ).bind(token, user.id, expira_em).run();

  return json({ ok: true, token, email: user.email });
}

/* ============================================================
 * LOGOUT ADMIN
 * ============================================================ */
async function logout({ request, env }){
  const token = (request.headers.get('Authorization') || '')
    .replace('Bearer ', '').trim();
  if (token){
    await env.DB.prepare('DELETE FROM sessoes WHERE token = ?').bind(token).run();
  }
  return json({ ok: true });
}

async function me({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  return json({ ok: true, email: user.email });
}

/* ============================================================
 * PRODUTOS
 * ============================================================ */
async function listarProdutos({ env }){
  const { results } = await env.DB.prepare(
    'SELECT * FROM produtos WHERE ativo = 1 ORDER BY categoria, ordem, nome'
  ).all();
  return json({ ok: true, produtos: results });
}

async function listarTodosProdutos({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);

  const { results } = await env.DB.prepare(
    'SELECT * FROM produtos ORDER BY categoria, ordem, nome'
  ).all();
  return json({ ok: true, produtos: results });
}

async function criarProduto({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);

  const p = await request.json();
  if (!p.nome || !p.categoria) return erro('Nome e categoria obrigatórios');

  const result = await env.DB.prepare(
    `INSERT INTO produtos
       (nome, categoria, subcategoria, volume, preco, tag, imagem_url, ativo, ordem)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    p.nome, p.categoria, p.subcategoria || null, p.volume || null,
    p.preco || null, p.tag || null, p.imagem_url || null,
    p.ativo !== undefined ? p.ativo : 1, p.ordem || 0
  ).run();

  return json({ ok: true, id: result.meta.last_row_id });
}

async function editarProduto({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);

  const p = await request.json();
  if (!p.id) return erro('ID obrigatório');

  await env.DB.prepare(
    `UPDATE produtos
        SET nome=?, categoria=?, subcategoria=?, volume=?, preco=?,
            tag=?, imagem_url=?, ativo=?, ordem=?
      WHERE id=?`
  ).bind(
    p.nome, p.categoria, p.subcategoria || null, p.volume || null,
    p.preco || null, p.tag || null, p.imagem_url || null,
    p.ativo !== undefined ? p.ativo : 1, p.ordem || 0, p.id
  ).run();

  return json({ ok: true });
}

async function deletarProduto({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);

  const id = new URL(request.url).searchParams.get('id');
  if (!id) return erro('ID obrigatório');

  await env.DB.prepare('DELETE FROM produtos WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

async function uploadImagem({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);

  const formData = await request.formData();
  const file = formData.get('file');
  if (!file) return erro('Nenhum arquivo enviado');

  const ext = file.name.split('.').pop().toLowerCase();
  const permitidos = ['jpg','jpeg','png','webp','gif'];
  if (!permitidos.includes(ext)) return erro('Formato não permitido');

  const nome = `${Date.now()}-${gerarToken().slice(0, 8)}.${ext}`;

  await env.BUCKET.put(nome, file.stream(), {
    httpMetadata: { contentType: file.type }
  });

  const url = `${env.R2_PUBLIC_URL}/${nome}`;
  return json({ ok: true, url });
}

/* ============================================================
 * CLIENTE — CADASTRO
 * ============================================================ */
async function cadastrarCliente({ request, env }){
  const { nome, email, senha } = await request.json();

  if (!nome || !email || !senha) return erro('Nome, email e senha obrigatórios');
  if (senha.length < 6) return erro('Senha precisa ter ao menos 6 caracteres');
  if (!email.includes('@')) return erro('Email inválido');

  const jaExiste = await env.DB.prepare(
    'SELECT id FROM clientes WHERE email = ?'
  ).bind(email).first();
  if (jaExiste) return erro('Já existe uma conta com esse email', 409);

  const salt = gerarSalt();
  const senha_hash = await hashSenha(senha, salt);

  const result = await env.DB.prepare(
    'INSERT INTO clientes (nome, email, senha_hash, salt) VALUES (?, ?, ?, ?)'
  ).bind(nome, email, senha_hash, salt).run();

  const clienteId = result.meta.last_row_id;

  // Cria sessão automaticamente
  const token = gerarToken();
  const expira_em = new Date(Date.now() + SESSAO_DURACAO_HORAS * 3600 * 1000)
    .toISOString().slice(0, 19).replace('T', ' ');

  await env.DB.prepare(
    'INSERT INTO sessoes_cliente (token, cliente_id, expira_em) VALUES (?, ?, ?)'
  ).bind(token, clienteId, expira_em).run();

  return json({
    ok: true,
    token,
    cliente: { id: clienteId, nome, email, foto_url: null }
  });
}

/* ============================================================
 * CLIENTE — LOGIN
 * ============================================================ */
async function loginCliente({ request, env }){
  const { email, senha } = await request.json();
  if (!email || !senha) return erro('Email e senha obrigatórios');

  const cli = await env.DB.prepare(
    'SELECT * FROM clientes WHERE email = ?'
  ).bind(email).first();
  if (!cli) return erro('Email ou senha inválidos', 401);

  const tentativa = await hashSenha(senha, cli.salt);
  if (tentativa !== cli.senha_hash) return erro('Email ou senha inválidos', 401);

  const token = gerarToken();
  const expira_em = new Date(Date.now() + SESSAO_DURACAO_HORAS * 3600 * 1000)
    .toISOString().slice(0, 19).replace('T', ' ');

  await env.DB.prepare(
    'INSERT INTO sessoes_cliente (token, cliente_id, expira_em) VALUES (?, ?, ?)'
  ).bind(token, cli.id, expira_em).run();

  return json({
    ok: true,
    token,
    cliente: { id: cli.id, nome: cli.nome, email: cli.email, foto_url: cli.foto_url }
  });
}

/* ============================================================
 * CLIENTE — LOGOUT
 * ============================================================ */
async function logoutCliente({ request, env }){
  const token = (request.headers.get('Authorization') || '')
    .replace('Bearer ', '').trim();
  if (token){
    await env.DB.prepare('DELETE FROM sessoes_cliente WHERE token = ?').bind(token).run();
  }
  return json({ ok: true });
}

/* ============================================================
 * CLIENTE — ME
 * ============================================================ */
async function meCliente({ request, env }){
  const cli = await autenticarCliente(request, env);
  if (!cli) return erro('Não autenticado', 401);
  return json({
    ok: true,
    cliente: { id: cli.id, nome: cli.nome, email: cli.email, foto_url: cli.foto_url }
  });
}