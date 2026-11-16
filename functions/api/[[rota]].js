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
    
    // Categorias
    if (rota === 'categorias' && metodo === 'GET') return listarCategorias(context);
    if (rota === 'admin/categorias' && metodo === 'GET') return listarCategorias(context);
    if (rota === 'categorias' && metodo === 'POST') return criarCategoria(context);
    if (rota === 'categoria' && metodo === 'DELETE') return deletarCategoria(context);

    // Produtos (Vitrine)
    if (rota === 'produtos' && metodo === 'GET') return listarProdutos(context);
    if (rota === 'admin/produtos' && metodo === 'GET') return listarTodosProdutos(context);
    if (rota === 'produtos' && metodo === 'POST') return criarProduto(context);
    if (rota === 'produto' && metodo === 'PUT') return editarProduto(context);
    if (rota === 'produto' && metodo === 'DELETE') return deletarProduto(context);
    if (rota === 'upload' && metodo === 'POST') return uploadImagem(context);

    // REGISTRO DE BARRAS (Catálogo)
    if (rota === 'barras/buscar' && metodo === 'GET') return buscarPorCodigoBarras(context);
    if (rota === 'admin/registro-barras' && metodo === 'GET') return listarRegistroBarras(context);
    if (rota === 'admin/registro-barras' && metodo === 'POST') return salvarRegistroBarras(context);
    if (rota === 'admin/registro-barras' && metodo === 'DELETE') return deletarRegistroBarras(context);
    
    // PDV (Caixa Rápido)
    if (rota === 'pdv/buscar' && metodo === 'GET') return buscarProdutoPdv(context);
    
    // Configurações
    if (rota === 'config/status' && metodo === 'GET') return getStatusLoja(context);
    if (rota === 'config/status' && metodo === 'PUT') return setStatusLoja(context);

    // Cliente
    if (rota === 'cliente/cadastro' && metodo === 'POST') return cadastrarCliente(context);
    if (rota === 'cliente/login' && metodo === 'POST') return loginCliente(context);
    if (rota === 'cliente/logout' && metodo === 'POST') return logoutCliente(context);
    if (rota === 'cliente/me' && metodo === 'GET') return meCliente(context);
    if (rota === 'cliente/endereco' && metodo === 'PUT') return atualizarEnderecoCliente(context);
    
    // Google OAuth
    if (rota === 'cliente/auth-google' && metodo === 'GET') return iniciarGoogle(context);
    if (rota === 'cliente/auth-google/callback' && metodo === 'GET') return callbackGoogle(context);

    // Pedidos
    if (rota === 'pedidos' && metodo === 'POST') return criarPedido(context);
    if (rota === 'admin/pedidos' && metodo === 'GET') return listarPedidos(context);
    if (rota === 'admin/pedido/status' && metodo === 'PUT') return atualizarStatusPedido(context);

    // Financeiro
    if (rota === 'admin/financeiro' && metodo === 'GET') return listarFinanceiro(context);
    if (rota === 'admin/financeiro' && metodo === 'POST') return criarTransacao(context);
    if (rota === 'admin/financeiro' && metodo === 'DELETE') return deletarTransacao(context);
    
    if (rota === 'admin/fluxo' && metodo === 'GET') return listarFluxo(context);
    if (rota === 'admin/fluxo' && metodo === 'POST') return criarFluxo(context);
    if (rota === 'admin/fluxo' && metodo === 'DELETE') return deletarFluxo(context);
    if (rota === 'admin/financeiro/fechar' && metodo === 'POST') return fecharCaixa(context);
    if (rota === 'admin/financeiro/status' && metodo === 'GET') return statusCaixa(context);

    return erro('Rota não encontrada: ' + rota, 404);
  } catch (e){
    console.error('[api] erro:', e);
    return erro('Erro interno: ' + e.message, 500);
  }
}

/* ============================================================
 * PDV E REGISTRO DE BARRAS
 * ============================================================ */
async function buscarProdutoPdv({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  
  const codigo = new URL(request.url).searchParams.get('codigo');
  if (!codigo) return erro('Código não informado');

  // Busca APENAS no banco local (registro_barras)
  const produto = await env.DB.prepare('SELECT * FROM registro_barras WHERE codigo_barras = ?').bind(codigo).first();
  
  if (!produto) return erro('Código não encontrado', 404);
  
  return json({ ok: true, produto });
}

async function buscarPorCodigoBarras({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  
  const codigo = new URL(request.url).searchParams.get('codigo');
  if (!codigo) return erro('Código de barras não informado');

  const registroLocal = await env.DB.prepare('SELECT * FROM registro_barras WHERE codigo_barras = ?').bind(codigo).first();
  if (registroLocal) return json({ ok: true, produto: registroLocal, origem: 'local' });

  try {
    const SEU_TOKEN_SI5 = env.SI5_TOKEN; 
    if (!SEU_TOKEN_SI5) return erro('Produto não encontrado. Token SI5 não configurado.', 404);

    const res = await fetch(`https://global.si5.com.br/api/produtos/${codigo}`, {
      headers: { 'Authorization': `Bearer ${SEU_TOKEN_SI5}`, 'Accept': 'application/json' }
    });
    
    if (!res.ok) throw new Error('API não encontrou o produto');
    const item = await res.json();
    
    if (item) {
      const produtoApi = {
        nome: item.produto || 'Produto sem nome',
        marca: item.marca || null,
        codigo_barras: codigo,
        preco: null,
        origem: 'api'
      };
      return json({ ok: true, produto: produtoApi, origem: 'api' });
    }
    throw new Error('Produto não encontrado na API');
  } catch (e) {
    return erro('Produto não encontrado.', 404);
  }
}

async function listarRegistroBarras({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  const { results } = await env.DB.prepare('SELECT * FROM registro_barras ORDER BY criado_em DESC').all();
  return json({ ok: true, registros: results });
}

async function salvarRegistroBarras({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  const p = await request.json();
  
  if (!p.codigo_barras || !p.nome) return erro('Código e Nome são obrigatórios');
  
  await env.DB.prepare(
    `INSERT OR REPLACE INTO registro_barras (codigo_barras, nome, marca, preco) 
     VALUES (?, ?, ?, ?)`
  ).bind(p.codigo_barras, p.nome, p.marca || null, p.preco || null).run();
  
  return json({ ok: true });
}

async function deletarRegistroBarras({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  const id = new URL(request.url).searchParams.get('id');
  if (!id) return erro('ID obrigatório');
  await env.DB.prepare('DELETE FROM registro_barras WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

/* ============================================================
 * DEMAIS FUNÇÕES
 * ============================================================ */
async function setup({ request, env }){
  const total = await env.DB.prepare('SELECT COUNT(*) AS n FROM usuarios').first();
  if (total.n > 0) return erro('Setup já foi feito.', 403);
  const { email, senha } = await request.json();
  if (!email || !senha) return erro('Email e senha obrigatórios');
  if (senha.length < 6) return erro('Senha curta');
  const salt = gerarSalt();
  const senha_hash = await hashSenha(senha, salt);
  await env.DB.prepare('INSERT INTO usuarios (email, senha_hash, salt) VALUES (?, ?, ?)').bind(email, senha_hash, salt).run();
  return json({ ok: true, msg: 'Admin criado!' });
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

async function listarCategorias({ env }){
  const { results } = await env.DB.prepare('SELECT * FROM categorias ORDER BY ordem ASC, nome ASC').all();
  return json({ ok: true, categorias: results });
}

async function criarCategoria({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  const p = await request.json();
  if (!p.nome) return erro('Nome obrigatório');
  const slug = p.nome.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  const jaExiste = await env.DB.prepare('SELECT id FROM categorias WHERE slug = ? OR nome = ?').bind(slug, p.nome).first();
  if (jaExiste) return erro('Já existe.', 409);
  await env.DB.prepare('INSERT INTO categorias (nome, slug, ordem) VALUES (?, ?, ?)').bind(p.nome, slug, p.ordem || 0).run();
  return json({ ok: true });
}

async function deletarCategoria({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  const id = new URL(request.url).searchParams.get('id');
  const cat = await env.DB.prepare('SELECT slug FROM categorias WHERE id = ?').bind(id).first();
  if (!cat) return erro('Não encontrada', 404);
  const temProdutos = await env.DB.prepare('SELECT COUNT(*) AS n FROM produtos WHERE categoria = ?').bind(cat.slug).first();
  if (temProdutos.n > 0) return erro('Existem produtos nessa categoria.', 400);
  await env.DB.prepare('DELETE FROM categorias WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

async function listarProdutos({ env }){
  const { results } = await env.DB.prepare('SELECT * FROM produtos WHERE ativo = 1 ORDER BY ordem, nome').all();
  return json({ ok: true, produtos: results });
}

async function listarTodosProdutos({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  const { results } = await env.DB.prepare('SELECT * FROM produtos ORDER BY ordem, nome').all();
  return json({ ok: true, produtos: results });
}

async function criarProduto({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  const p = await request.json();
  if (!p.nome || !p.categoria) return erro('Nome e categoria obrigatórios');
  const result = await env.DB.prepare(
    `INSERT INTO produtos (nome, categoria, subcategoria, volume, preco, tag, imagem_url, ativo, ordem, variacoes, codigo_barras, estoque) 
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    p.nome, p.categoria, p.subcategoria || null, p.volume || null, 
    p.preco || null, p.tag || null, p.imagem_url || null, 
    p.ativo !== undefined ? p.ativo : 1, p.ordem || 0, p.variacoes || null,
    p.codigo_barras || null, p.estoque || 0
  ).run();
  return json({ ok: true, id: result.meta.last_row_id });
}

async function editarProduto({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  const p = await request.json();
  if (!p.id) return erro('ID obrigatório');
  await env.DB.prepare(
    `UPDATE produtos SET nome=?, categoria=?, subcategoria=?, volume=?, preco=?, tag=?, imagem_url=?, ativo=?, ordem=?, variacoes=?, codigo_barras=?, estoque=? WHERE id=?`
  ).bind(
    p.nome, p.categoria, p.subcategoria || null, p.volume || null, 
    p.preco || null, p.tag || null, p.imagem_url || null, 
    p.ativo !== undefined ? p.ativo : 1, p.ordem || 0, p.variacoes || null,
    p.codigo_barras || null, p.estoque || 0, p.id
  ).run();
  return json({ ok: true });
}

async function deletarProduto({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  const id = new URL(request.url).searchParams.get('id');
  await env.DB.prepare('DELETE FROM produtos WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

async function uploadImagem({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  const formData = await request.formData();
  const file = formData.get('file');
  if (!file) return erro('Nenhum arquivo');
  const ext = file.name.split('.').pop().toLowerCase();
  const nome = `${Date.now()}-${gerarToken().slice(0, 8)}.${ext}`;
  await env.BUCKET.put(nome, file.stream(), { httpMetadata: { contentType: file.type } });
  return json({ ok: true, url: `${env.R2_PUBLIC_URL}/${nome}` });
}

async function getStatusLoja({ env }){
  try {
    const row = await env.DB.prepare("SELECT valor FROM configuracoes WHERE chave = 'status_loja'").first();
    return json({ ok: true, status: row ? row.valor : 'fechado' });
  } catch (e) { return json({ ok: true, status: 'fechado' }); }
}

async function setStatusLoja({ request, env }){
  try {
    const user = await autenticar(request, env);
    if (!user) return erro('Não autenticado', 401);
    const { status } = await request.json();
    await env.DB.prepare("INSERT OR REPLACE INTO configuracoes (chave, valor) VALUES ('status_loja', ?)").bind(status).run();
    return json({ ok: true, status });
  } catch (e) { return erro('Erro: ' + e.message, 500); }
}

async function cadastrarCliente({ request, env }){
  const { nome, email, senha } = await request.json();
  if (!nome || !email || !senha) return erro('Dados incompletos');
  if (senha.length < 6) return erro('Senha curta');
  if (!email.includes('@')) return erro('Email inválido');
  const jaExiste = await env.DB.prepare('SELECT id FROM clientes WHERE email = ?').bind(email).first();
  if (jaExiste) return erro('Email já cadastrado', 409);
  const salt = gerarSalt();
  const senha_hash = await hashSenha(senha, salt);
  const result = await env.DB.prepare('INSERT INTO clientes (nome, email, senha_hash, salt) VALUES (?, ?, ?, ?)').bind(nome, email, senha_hash, salt).run();
  const token = gerarToken();
  const expira_em = new Date(Date.now() + SESSAO_DURACAO_HORAS * 3600 * 1000).toISOString().slice(0, 19).replace('T', ' ');
  await env.DB.prepare('INSERT INTO sessoes_cliente (token, cliente_id, expira_em) VALUES (?, ?, ?)').bind(token, result.meta.last_row_id, expira_em).run();
  return json({ ok: true, token, cliente: { id: result.meta.last_row_id, nome, email } });
}

async function loginCliente({ request, env }){
  const { email, senha } = await request.json();
  if (!email || !senha) return erro('Dados incompletos');
  const cli = await env.DB.prepare('SELECT * FROM clientes WHERE email = ?').bind(email).first();
  if (cli) {
    if (!cli.senha_hash) return erro('Conta usa Google.', 401);
    const tentativa = await hashSenha(senha, cli.salt);
    if (tentativa !== cli.senha_hash) return erro('Senha inválida', 401);
    const token = gerarToken();
    const expira_em = new Date(Date.now() + SESSAO_DURACAO_HORAS * 3600 * 1000).toISOString().slice(0, 19).replace('T', ' ');
    await env.DB.prepare('INSERT INTO sessoes_cliente (token, cliente_id, expira_em) VALUES (?, ?, ?)').bind(token, cli.id, expira_em).run();
    return json({ ok: true, token, cliente: { id: cli.id, nome: cli.nome, email: cli.email, endereco: cli.endereco, numero: cli.numero } });
  }
  const admin = await env.DB.prepare('SELECT * FROM usuarios WHERE email = ?').bind(email).first();
  if (admin) {
    const tentativa = await hashSenha(senha, admin.salt);
    if (tentativa !== admin.senha_hash) return erro('Senha inválida', 401);
    const token = gerarToken();
    const expira_em = new Date(Date.now() + SESSAO_DURACAO_HORAS * 3600 * 1000).toISOString().slice(0, 19).replace('T', ' ');
    await env.DB.prepare('INSERT INTO sessoes (token, usuario_id, expira_em) VALUES (?, ?, ?)').bind(token, admin.id, expira_em).run();
    return json({ ok: true, isAdmin: true, token, email: admin.email });
  }
  return erro('Login inválido', 401);
}

async function logoutCliente({ request, env }){
  const token = (request.headers.get('Authorization') || '').replace('Bearer ', '').trim();
  if (token) await env.DB.prepare('DELETE FROM sessoes_cliente WHERE token = ?').bind(token).run();
  return json({ ok: true });
}

async function meCliente({ request, env }){
  const cli = await autenticarCliente(request, env);
  if (!cli) return erro('Não autenticado', 401);
  return json({ ok: true, cliente: cli });
}

async function atualizarEnderecoCliente({ request, env }){
  const cli = await autenticarCliente(request, env);
  if (!cli) return erro('Não autenticado', 401);
  const { endereco, numero } = await request.json();
  await env.DB.prepare('UPDATE clientes SET endereco = ?, numero = ? WHERE id = ?').bind(endereco, numero, cli.id).run();
  return json({ ok: true, cliente: { ...cli, endereco, numero } });
}

async function criarPedido({ request, env }){
  const cli = await autenticarCliente(request, env);
  if (!cli) return erro('Não autenticado', 401);
  const { itens, total, pagamento, endereco, numero, observacao } = await request.json();
  if (!itens || !pagamento) return erro('Dados incompletos');
  const enderecoCompleto = `${endereco}, ${numero}`;
  const result = await env.DB.prepare(`INSERT INTO pedidos (cliente_id, total, metodo_pagamento, endereco, observacao) VALUES (?, ?, ?, ?, ?)`).bind(cli.id, total, pagamento, enderecoCompleto, observacao || null).run();
  const pedidoId = result.meta.last_row_id;
  for (let item of itens) {
    let p = typeof item.preco === 'string' ? parseFloat(item.preco.replace('R$', '').replace(',', '.')) : item.preco;
    await env.DB.prepare(`INSERT INTO pedido_itens (pedido_id, produto_id, quantidade, preco_unitario, variacao) VALUES (?, ?, ?, ?, ?)`).bind(pedidoId, item.id, item.quantidade, p, item.variacao || null).run();
  }
  return json({ ok: true, pedidoId });
}

async function listarPedidos({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  const { results } = await env.DB.prepare(`SELECT p.*, c.nome as cliente_nome FROM pedidos p JOIN clientes c ON c.id = p.cliente_id WHERE p.criado_em >= datetime('now', '-72 hours') ORDER BY p.criado_em DESC`).all();
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

async function listarFinanceiro({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  const url = new URL(request.url);
  const ano = url.searchParams.get('ano'), mes = url.searchParams.get('mes');
  const { results } = await env.DB.prepare('SELECT * FROM financeiro WHERE data LIKE ? ORDER BY data DESC, criado_em DESC').bind(`${ano}-${String(mes).padStart(2, '0')}%`).all();
  return json({ ok: true, transacoes: results });
}

async function criarTransacao({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  const { data, valor, metodo_pagamento } = await request.json();
  await env.DB.prepare('INSERT INTO financeiro (data, valor, metodo_pagamento) VALUES (?, ?, ?)').bind(data, valor, metodo_pagamento).run();
  return json({ ok: true });
}

async function deletarTransacao({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  const id = new URL(request.url).searchParams.get('id');
  await env.DB.prepare('DELETE FROM financeiro WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

async function listarFluxo({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  const url = new URL(request.url);
  const ano = url.searchParams.get('ano'), mes = url.searchParams.get('mes');
  const { results } = await env.DB.prepare('SELECT * FROM fluxo_caixa WHERE data LIKE ? ORDER BY data DESC, criado_em DESC').bind(`${ano}-${String(mes).padStart(2, '0')}%`).all();
  return json({ ok: true, fluxo: results });
}

async function criarFluxo({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  const { data, tipo, valor, descricao } = await request.json();
  await env.DB.prepare('INSERT INTO fluxo_caixa (data, tipo, valor, descricao) VALUES (?, ?, ?, ?)').bind(data, tipo, valor, descricao).run();
  return json({ ok: true });
}

async function deletarFluxo({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  const id = new URL(request.url).searchParams.get('id');
  await env.DB.prepare('DELETE FROM fluxo_caixa WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

async function statusCaixa({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  const url = new URL(request.url);
  const ano = url.searchParams.get('ano'), mes = url.searchParams.get('mes');
  const { results } = await env.DB.prepare('SELECT * FROM caixa_status WHERE data LIKE ?').bind(`${ano}-${String(mes).padStart(2, '0')}%`).all();
  return json({ ok: true, status: results });
}

async function fecharCaixa({ request, env }){
  const user = await autenticar(request, env);
  if (!user) return erro('Não autenticado', 401);
  const { data, total } = await request.json();
  await env.DB.prepare('INSERT OR REPLACE INTO caixa_status (data, fechado, total) VALUES (?, 1, ?)').bind(data, total).run();
  await env.DB.prepare('INSERT INTO fluxo_caixa (data, tipo, valor, descricao) VALUES (?, "entrada", ?, ?)').bind(data, total, `Fechamento - ${data.split('-').reverse().join('/')}`).run();
  return json({ ok: true });
}

async function iniciarGoogle({ env }){
  return erro('Google OAuth desativado', 400);
}

async function callbackGoogle({ request, env }){
  return erro('Google OAuth desativado', 400);
}
