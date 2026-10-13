/* ============================================================
 * Green Conveniência — Backend completo (single-file)
 *
 * Rotas:
 *   POST   /api/setup         → cria o primeiro admin (só 1x)
 *   POST   /api/login         → faz login, retorna token
 *   POST   /api/logout        → encerra sessão
 *   GET    /api/me            → retorna usuário logado
 *   GET    /api/produtos      → lista produtos ativos (público)
 *   POST   /api/produtos      → cria produto (auth)
 *   PUT    /api/produto       → edita produto (auth)
 *   DELETE /api/produto?id=X  → deleta produto (auth)
 *   POST   /api/upload        → upload de imagem (auth)
 * ============================================================ */

const SESSAO_DURACAO_HORAS = 24 * 7; // 7 dias

/* ---------- Helpers ---------- */
const json = (data, status = 200) => Response.json(data, { status });
const erro = (msg,  status = 400) => Response.json({ erro: msg }, { status });

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

/* ============================================================
 * ROTEADOR
 * ============================================================ */
export async function onRequest(context){
  const { request, env } = context;
  const url    = new URL(request.url);
  const rota   = url.pathname.replace('/api/', '').replace(/\/$/, '');
  const metodo = request.method;

  try {
    if (rota === 'setup'    && metodo === 'POST')   return setup(context);
    if (rota === 'login'    && metodo === 'POST')   return login(context);
    if (rota === 'logout'   && metodo === 'POST')   return logout(context);
    if (rota === 'me'       && metodo === 'GET')    return me(context);
    if (rota === 'produtos' && metodo === 'GET')    return listarProdutos(context);
    if (rota === 'produtos' && metodo === 'POST')   return criarProduto(context);
    if (rota === 'produto'  && metodo === 'PUT')    return editarProduto(context);
    if (rota === 'produto'  && metodo === 'DELETE') return deletarProduto(context);
    if (rota === 'upload'   && metodo === 'POST')   return uploadImagem(context);

    return erro('Rota não encontrada: ' + rota, 404);
  } catch (e){
    console.error('[api] erro:', e);
    return erro('Erro interno: ' + e.message, 500);
  }
}

/* ============================================================
 * SETUP — cria o primeiro admin (só funciona se não houver nenhum)
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
 * LOGIN
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
 * LOGOUT
 * ============================================================ */
async function logout({ request, env }){
  const token = (request.headers.get('Authorization') || '')
    .replace('Bearer ', '').trim();
  if (token){
    await env.DB.prepare('DELETE FROM sessoes WHERE token = ?').bind(token).run();
  }
  return json({ ok: true });
}

/* ============================================================
 * ME — dados do usuário logado
 * ============================================================ */
async function me({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  return json({ ok: true, email: user.email });
}

/* ============================================================
 * LISTAR PRODUTOS (público)
 * ============================================================ */
async function listarProdutos({ env }){
  const { results } = await env.DB.prepare(
    'SELECT * FROM produtos WHERE ativo = 1 ORDER BY categoria, ordem, nome'
  ).all();
  return json({ ok: true, produtos: results });
}

/* ============================================================
 * CRIAR PRODUTO (auth)
 * ============================================================ */
async function criarProduto({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);

  const p = await request.json();
  if (!p.nome || !p.categoria) return erro('Nome e categoria obrigatórios');

  const result = await env.DB.prepare(
    `INSERT INTO produtos
       (nome, categoria, subcategoria, volume, preco, tag, imagem_url, ordem)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    p.nome, p.categoria, p.subcategoria || null, p.volume || null,
    p.preco || null, p.tag || null, p.imagem_url || null, p.ordem || 0
  ).run();

  return json({ ok: true, id: result.meta.last_row_id });
}

/* ============================================================
 * EDITAR PRODUTO (auth)
 * ============================================================ */
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

/* ============================================================
 * DELETAR PRODUTO (auth)
 * ============================================================ */
async function deletarProduto({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);

  const id = new URL(request.url).searchParams.get('id');
  if (!id) return erro('ID obrigatório');

  await env.DB.prepare('DELETE FROM produtos WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

/* ============================================================
 * UPLOAD DE IMAGEM → R2
 * ============================================================ */
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