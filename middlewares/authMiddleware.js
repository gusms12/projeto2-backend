import jwt from 'jsonwebtoken';

// 🧩 Middleware para verificar token JWT
export const verificarToken = (req, res, next) => {
  try {
    // Pega o token do cabeçalho Authorization
    const token = req.headers.authorization?.replace('Bearer ', '');

    if (!token) {
      return res.status(401).json({
        erro: 'Token não fornecido',
        mensagem: 'Você precisa estar logado para acessar esta rota'
      });
    }

    // Verifica e decodifica o token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.usuario = decoded; // Armazena os dados do usuário na requisição
    next();
  } catch (erro) {
    return res.status(401).json({
      erro: 'Token inválido',
      mensagem: 'Seu token expirou ou é inválido. Faça login novamente.'
    });
  }
};

// 🧩 Middleware para verificar tipo de usuário (ex: admin, aluno, mentor)
export const verificarTipoUsuario = (tipoPermitido) => {
  return (req, res, next) => {
    if (!req.usuario || req.usuario.tipo !== tipoPermitido) {
      return res.status(403).json({
        erro: 'Acesso negado',
        mensagem: `Esta rota é apenas para ${tipoPermitido}s`
      });
    }
    next();
  };
};
