/* ============================================================
 * Green Conveniência — Backend completo (single-file)
 * ============================================================ */

const SESSAO_DURACAO_HORAS = 24 * 7;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

const json = (data, status = 200) => Response.json(data, { status, headers: CORS });
const erro = (msg, status = 400) => Response.json({ erro: msg }, { status, headers: CORS });
const buf2hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');

function gerarToken(){ const b = new Uint8Array(32); crypto.getRandomValues(b); return buf2hex(b); }
function gerarSalt(){ const b = new Uint8Array(16); crypto.getRandomValues(b); return buf2hex(b); }

async function hashSenha(senha, salt){
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(senha), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name:'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash:'SHA-256' }, key, 256);
  return buf2hex(bits);
}

async function autenticar(request, env){
  const token = (request.headers.get('Authorization') || '').replace('Bearer ', '').trim();
  if (!token) return null;
  return await env.DB.prepare(`SELECT s.usuario_id, u.email FROM sessoes s JOIN usuarios u ON u.id = s.usuario_id WHERE s.token = ? AND s.expira_em > datetime('now')`).bind(token).first();
}

async function autenticarCliente(request, env){
  const token = (request.headers.get('Authorization') || '').replace('Bearer ', '').trim();
  if (!token) return null;
  return await env.DB.prepare(`SELECT c.id, c.nome, c.email, c.foto_url, c.endereco, c.numero FROM sessoes_cliente s JOIN clientes c ON c.id = s.cliente_id WHERE s.token = ? AND s.expira_em > datetime('now')`).bind(token).first();
}

/* ============================================================
 * ROTEADOR
 * ============================================================ */
export async function onRequest(context){
  const { request, env } = context;
  const url = new URL(request.url);
  const rota = url.pathname.replace('/api/', '').replace(/\/$/, '');
  const metodo = request.method;

  if (metodo === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  try {
    // Admin
    if (rota === 'setup' && metodo === 'POST') return setup(context);
    if (rota === 'login' && metodo === 'POST') return login(context);
    if (rota === 'logout' && metodo === 'POST') return logout(context);
    if (rota === 'me' && metodo === 'GET') return me(context);
    
    // Produtos
    if (rota === 'produtos' && metodo === 'GET') return listarProdutos(context);
    if (rota === 'admin/produtos' && metodo === 'GET') return listarTodosProdutos(context);
    if (rota === 'produtos' && metodo === 'POST') return criarProduto(context);
    if (rota === 'produto' && metodo === 'PUT') return editarProduto(context);
    if (rota === 'produto' && metodo === 'DELETE') return deletarProduto(context);
    if (rota === 'upload' && metodo === 'POST') return uploadImagem(context);
    
    // Configurações
    if (rota === 'config/status' && metodo === 'GET') return getStatusLoja(context);
    if (rota === 'config/status' && metodo === 'PUT') return setStatusLoja(context);

    // Cliente
    if (rota === 'cliente/cadastro' && metodo === 'POST') return cadastrarCliente(context);
    if (rota === 'cliente/login' && metodo === 'POST') return loginCliente(context);
    if (rota === 'cliente/logout' && metodo === 'POST') return logoutCliente(context);
    if (rota === 'cliente/me' && metodo === 'GET') return meCliente(context);
    if (rota === 'cliente/endereco' && metodo === 'PUT') return atualizarEnderecoCliente(context);
    if (rota === 'cliente/auth-google' && metodo === 'GET') return iniciarGoogle(context);
    if (rota === 'cliente/auth-google/callback' && metodo === 'GET') return callbackGoogle(context);

    // Pedidos
    if (rota === 'pedidos' && metodo === 'POST') return criarPedido(context);
    if (rota === 'admin/pedidos' && metodo === 'GET') return listarPedidos(context);
    if (rota === 'admin/pedido/status' && metodo === 'PUT') return atualizarStatusPedido(context);

    return erro('Rota não encontrada: ' + rota, 404);
  } catch (e){
    console.error('[api] erro:', e);
    return erro('Erro interno: ' + e.message, 500);
  }
}

/* ============================================================
 * ADMIN — SETUP / LOGIN / LOGOUT / ME
 * ============================================================ */
async function setup({ request, env }){
  const total = await env.DB.prepare('SELECT COUNT(*) AS n FROM usuarios').first();
  if (total.n > 0) return erro('Setup já foi feito. Faça login normalmente.', 403);
  const { email, senha } = await request.json();
  if (!email || !senha) return erro('Email e senha obrigatórios');
  if (senha.length < 6) return erro('Senha precisa ter ao menos 6 caracteres');
  const salt = gerarSalt();
  const senha_hash = await hashSenha(senha, salt);
  await env.DB.prepare('INSERT INTO usuarios (email, senha_hash, salt) VALUES (?, ?, ?)').bind(email, senha_hash, salt).run();
  return json({ ok: true, msg: 'Admin criado! Agora faça login em /api/login' });
}

async function login({ request, env }){
  const { email, senha } = await request.json();
  if (!email || !senha) return erro('Email e senha obrigatórios');
  const user = await env.DB.prepare('SELECT * FROM usuarios WHERE email = ?').bind(email).first();
  if (!user) return erro('Email ou senha inválidos', 401);
  const tentativa = await hashSenha(senha, user.salt);
  if (tentativa !== user.senha_hash) return erro('Email ou senha inválidos', 401);
  const token = gerarToken();
  const expira_em = new Date(Date.now() + SESSAO_DURACAO_HORAS * 3600 * 1000).toISOString().slice(0, 19).replace('T', ' ');
  await env.DB.prepare('INSERT INTO sessoes (token, usuario_id, expira_em) VALUES (?, ?, ?)').bind(token, user.id, expira_em).run();
  return json({ ok: true, token, email: user.email });
}

async function logout({ request, env }){
  const token = (request.headers.get('Authorization') || '').replace('Bearer ', '').trim();
  if (token) await env.DB.prepare('DELETE FROM sessoes WHERE token = ?').bind(token).run();
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
  const { results } = await env.DB.prepare('SELECT * FROM produtos WHERE ativo = 1 ORDER BY categoria, ordem, nome').all();
  return json({ ok: true, produtos: results });
}

async function listarTodosProdutos({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  const { results } = await env.DB.prepare('SELECT * FROM produtos ORDER BY categoria, ordem, nome').all();
  return json({ ok: true, produtos: results });
}

async function criarProduto({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  const p = await request.json();
  if (!p.nome || !p.categoria) return erro('Nome e categoria obrigatórios');
  const result = await env.DB.prepare(`INSERT INTO produtos (nome, categoria, subcategoria, volume, preco, tag, imagem_url, ativo, ordem) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(p.nome, p.categoria, p.subcategoria || null, p.volume || null, p.preco || null, p.tag || null, p.imagem_url || null, p.ativo !== undefined ? p.ativo : 1, p.ordem || 0).run();
  return json({ ok: true, id: result.meta.last_row_id });
}

async function editarProduto({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  const p = await request.json();
  if (!p.id) return erro('ID obrigatório');
  await env.DB.prepare(`UPDATE produtos SET nome=?, categoria=?, subcategoria=?, volume=?, preco=?, tag=?, imagem_url=?, ativo=?, ordem=? WHERE id=?`).bind(p.nome, p.categoria, p.subcategoria || null, p.volume || null, p.preco || null, p.tag || null, p.imagem_url || null, p.ativo !== undefined ? p.ativo : 1, p.ordem || 0, p.id).run();
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
  await env.BUCKET.put(nome, file.stream(), { httpMetadata: { contentType: file.type } });
  const url = `${env.R2_PUBLIC_URL}/${nome}`;
  return json({ ok: true, url });
}

/* ============================================================
 * CONFIGURAÇÕES DA LOJA
 * ============================================================ */
async function getStatusLoja({ env }){
  try {
    const row = await env.DB.prepare("SELECT valor FROM configuracoes WHERE chave = 'status_loja'").first();
    return json({ ok: true, status: row ? row.valor : 'fechado' });
  } catch (e) {
    return json({ ok: true, status: 'fechado' });
  }
}

async function setStatusLoja({ request, env }){
  try {
    const user = await autenticar(request, env);
    if (!user) return erro('Não autenticado', 401);
    
    const { status } = await request.json();
    if (!['aberto', 'fechado'].includes(status)) return erro('Status inválido', 400);

    await env.DB.prepare(
      "INSERT OR REPLACE INTO configuracoes (chave, valor) VALUES ('status_loja', ?)"
    ).bind(status).run();
    
    return json({ ok: true, status });
  } catch (e) {
    console.error('Erro ao atualizar status:', e);
    return erro('Erro interno: ' + e.message, 500);
  }
}

/* ============================================================
 * CLIENTE — CADASTRO / LOGIN / LOGOUT / ME
 * ============================================================ */
async function cadastrarCliente({ request, env }){
  const { nome, email, senha } = await request.json();
  if (!nome || !email || !senha) return erro('Nome, email e senha obrigatórios');
  if (senha.length < 6) return erro('Senha precisa ter ao menos 6 caracteres');
  if (!email.includes('@')) return erro('Email inválido');
  const jaExiste = await env.DB.prepare('SELECT id FROM clientes WHERE email = ?').bind(email).first();
  if (jaExiste) return erro('Já existe uma conta com esse email', 409);
  const salt = gerarSalt();
  const senha_hash = await hashSenha(senha, salt);
  const result = await env.DB.prepare('INSERT INTO clientes (nome, email, senha_hash, salt) VALUES (?, ?, ?, ?)').bind(nome, email, senha_hash, salt).run();
  const clienteId = result.meta.last_row_id;
  const token = gerarToken();
  const expira_em = new Date(Date.now() + SESSAO_DURACAO_HORAS * 3600 * 1000).toISOString().slice(0, 19).replace('T', ' ');
  await env.DB.prepare('INSERT INTO sessoes_cliente (token, cliente_id, expira_em) VALUES (?, ?, ?)').bind(token, clienteId, expira_em).run();
  return json({ ok: true, isAdmin: false, token, cliente: { id: clienteId, nome, email, foto_url: null, endereco: null, numero: null } });
}

async function loginCliente({ request, env }){
  const { email, senha } = await request.json();
  if (!email || !senha) return erro('Email e senha obrigatórios');

  // 1. Tenta achar na tabela de CLIENTES
  const cli = await env.DB.prepare('SELECT * FROM clientes WHERE email = ?').bind(email).first();
  if (cli) {
    if (!cli.senha_hash) return erro('Essa conta usa login com Google. Clique em "Entrar com Google".', 401);
    const tentativa = await hashSenha(senha, cli.salt);
    if (tentativa !== cli.senha_hash) return erro('Email ou senha inválidos', 401);
    
    const token = gerarToken();
    const expira_em = new Date(Date.now() + SESSAO_DURACAO_HORAS * 3600 * 1000).toISOString().slice(0, 19).replace('T', ' ');
    await env.DB.prepare('INSERT INTO sessoes_cliente (token, cliente_id, expira_em) VALUES (?, ?, ?)').bind(token, cli.id, expira_em).run();
    
    return json({ ok: true, isAdmin: false, token, cliente: { id: cli.id, nome: cli.nome, email: cli.email, foto_url: cli.foto_url, endereco: cli.endereco, numero: cli.numero } });
  }

  // 2. Se não achou cliente, tenta achar na tabela de ADMIN (usuarios)
  const admin = await env.DB.prepare('SELECT * FROM usuarios WHERE email = ?').bind(email).first();
  if (admin) {
    const tentativa = await hashSenha(senha, admin.salt);
    if (tentativa !== admin.senha_hash) return erro('Email ou senha inválidos', 401);
    
    const token = gerarToken();
    const expira_em = new Date(Date.now() + SESSAO_DURACAO_HORAS * 3600 * 1000).toISOString().slice(0, 19).replace('T', ' ');
    await env.DB.prepare('INSERT INTO sessoes (token, usuario_id, expira_em) VALUES (?, ?, ?)').bind(token, admin.id, expira_em).run();
    
    return json({ ok: true, isAdmin: true, token, email: admin.email });
  }

  return erro('Email ou senha inválidos', 401);
}

async function logoutCliente({ request, env }){
  const token = (request.headers.get('Authorization') || '').replace('Bearer ', '').trim();
  if (token) await env.DB.prepare('DELETE FROM sessoes_cliente WHERE token = ?').bind(token).run();
  return json({ ok: true });
}

async function meCliente({ request, env }){
  const cli = await autenticarCliente(request, env);
  if (!cli) return erro('Não autenticado', 401);
  return json({ ok: true, cliente: { id: cli.id, nome: cli.nome, email: cli.email, foto_url: cli.foto_url, endereco: cli.endereco, numero: cli.numero } });
}

async function atualizarEnderecoCliente({ request, env }){
  const cli = await autenticarCliente(request, env);
  if (!cli) return erro('Não autenticado', 401);
  const { endereco, numero } = await request.json();
  if (!endereco || !numero) return erro('Endereço e número são obrigatórios');
  await env.DB.prepare('UPDATE clientes SET endereco = ?, numero = ? WHERE id = ?').bind(endereco, numero, cli.id).run();
  return json({ ok: true, cliente: { ...cli, endereco, numero } });
}

/* ============================================================
 * CLIENTE — PEDIDOS
 * ============================================================ */
async function criarPedido({ request, env }){
  try {
    const cli = await autenticarCliente(request, env);
    if (!cli) return erro('Não autenticado. Faça login para pedir.', 401);

    const { itens, total, pagamento, endereco, numero, observacao } = await request.json();
    if (!itens || itens.length === 0) return erro('Carrinho vazio');
    if (!pagamento || !endereco || !numero) return erro('Dados incompletos');

    const enderecoCompleto = `${endereco}, ${numero}`;
    const result = await env.DB.prepare(
      `INSERT INTO pedidos (cliente_id, total, metodo_pagamento, endereco, observacao) 
       VALUES (?, ?, ?, ?, ?)`
    ).bind(cli.id, total, pagamento, enderecoCompleto, observacao || null).run();
    
    const pedidoId = result.meta.last_row_id;

    for (let item of itens) {
      // CORREÇÃO: Trata tanto string "R$ 4,25" quanto number 4.25
      let precoNumerico = item.preco;
      if (typeof item.preco === 'string') {
        precoNumerico = parseFloat(item.preco.replace('R$', '').replace(',', '.').trim());
      }
      
      await env.DB.prepare(
        `INSERT INTO pedido_itens (pedido_id, produto_id, quantidade, preco_unitario) 
         VALUES (?, ?, ?, ?)`
      ).bind(pedidoId, item.id, item.quantidade, precoNumerico).run();
    }

    // CORREÇÃO BLINDADA: Tenta atualizar o endereço, mas se falhar, não derruba o pedido.
    try {
      if (!cli.endereco || !cli.numero) {
        await env.DB.prepare('UPDATE clientes SET endereco = ?, numero = ? WHERE id = ?')
          .bind(endereco, numero, cli.id).run();
      }
    } catch (errEndereco) {
      console.error('Aviso: Erro ao salvar endereço no perfil, mas o pedido foi salvo com sucesso:', errEndereco);
    }

    return json({ ok: true, pedidoId });
  } catch (e) {
    console.error('Erro ao criar pedido:', e);
    return erro('Erro ao criar pedido: ' + e.message, 500);
  }
}

async function listarPedidos({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  const { results } = await env.DB.prepare(`SELECT p.*, c.nome as cliente_nome, c.email as cliente_email FROM pedidos p JOIN clientes c ON c.id = p.cliente_id ORDER BY p.criado_em DESC`).all();
  for (let p of results) {
    const itens = await env.DB.prepare(`SELECT pi.*, pr.nome as produto_nome FROM pedido_itens pi JOIN produtos pr ON pr.id = pi.produto_id WHERE pi.pedido_id = ?`).bind(p.id).all();
    p.itens = itens.results;
  }
  return json({ ok: true, pedidos: results });
}

async function atualizarStatusPedido({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  const { id, status } = await request.json();
  await env.DB.prepare('UPDATE pedidos SET status = ? WHERE id = ?').bind(status, id).run();
  return json({ ok: true });
}

/* ============================================================
 * CLIENTE — GOOGLE OAUTH
 * ============================================================ */
async function iniciarGoogle({ env }){
  const params = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: env.GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'online',
    prompt: 'select_account'
  });
  const url = 'https://accounts.google.com/o/oauth2/v2/auth?' + params.toString();
  return Response.redirect(url, 302);
}

async function callbackGoogle({ request, env }){
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const errorParam = url.searchParams.get('error');
  const site = env.SITE_URL;

  if (errorParam || !code) {
    return Response.redirect(site + '/?google_erro=' + encodeURIComponent(errorParam || 'sem_code'), 302);
  }

  try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: env.GOOGLE_CLIENT_ID,
        client_secret: env.GOOGLE_CLIENT_SECRET,
        redirect_uri: env.GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code'
      })
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token){
      console.error('[google] token error:', tokenData);
      return Response.redirect(site + '/?google_erro=token_falhou', 302);
    }

    const userRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { 'Authorization': 'Bearer ' + tokenData.access_token }
    });
    const guser = await userRes.json();
    if (!guser.email){
      return Response.redirect(site + '/?google_erro=email_falhou', 302);
    }

    let cli = await env.DB.prepare('SELECT * FROM clientes WHERE email = ?').bind(guser.email).first();

    if (!cli){
      const result = await env.DB.prepare(`INSERT INTO clientes (nome, email, google_id, foto_url) VALUES (?, ?, ?, ?)`).bind(guser.name || 'Usuário', guser.email, guser.id || null, guser.picture || null).run();
      cli = { id: result.meta.last_row_id, nome: guser.name || 'Usuário', email: guser.email, foto_url: guser.picture || null, endereco: null, numero: null };
    } else {
      if (!cli.foto_url || !cli.google_id){
        await env.DB.prepare('UPDATE clientes SET foto_url = ?, google_id = ? WHERE id = ?').bind(guser.picture || cli.foto_url, guser.id || null, cli.id).run();
        cli.foto_url = guser.picture || cli.foto_url;
      }
    }

    const token = gerarToken();
    const expira_em = new Date(Date.now() + SESSAO_DURACAO_HORAS * 3600 * 1000).toISOString().slice(0, 19).replace('T', ' ');
    await env.DB.prepare('INSERT INTO sessoes_cliente (token, cliente_id, expira_em) VALUES (?, ?, ?)').bind(token, cli.id, expira_em).run();

    const params = new URLSearchParams({
      google_token: token,
      google_nome: cli.nome || '',
      google_email: cli.email || '',
      google_foto: cli.foto_url || ''
    });
    return Response.redirect(site + '/?' + params.toString(), 302);

  } catch (e){
    console.error('[google] erro:', e);
    return Response.redirect(site + '/?google_erro=excecao', 302);
  }
}
