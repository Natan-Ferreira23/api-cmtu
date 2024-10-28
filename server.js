require('dotenv').config(); //trás a chave para o jwt
let express = require('express');
let app = express(); //express pacotes para o nodejs
let bCrypt = require("bcrypt"); //bcrypt para criptografar senhas
let db = require('./database/db');
let jwt = require('jsonwebtoken');
const SECRET_KEY = process.env.SECRET_KEY; //chave
let porta = 8079;

app.use(express.json());


//rota de cadastro de usuários
app.post("/cadastro", (req, res) => {
    const { email, senha } = req.body;
    const procuraEmail = "SELECT email FROM usuarios WHERE email = ? ";
    const insereUsuario = "INSERT INTO usuarios (email,senha) VALUES(?, ?)";
    if (!email || !senha) {
        return res.status(404).send("Email e senha são obrigatorios !")
    }
    try {
        const senhaHash = bCrypt.hashSync(senha, 10); //criptografa a senha do usuário
        // esta func procura se o email existe para poder cadastrar o usuário caso não exista
        db.query(procuraEmail, [email], (err, result) => {
            try {
                if (result.length > 0) {// email existe, logo não cadastra

                    return res.status(200).send("Email já existe na base de dados");

                } else { //email não existe, logo cadastra
                    db.query(insereUsuario, [email, senhaHash], (err, result) => {
                        try {
                            res.status(200).send("Usuário cadastrado com sucesso");
                        } catch (err) {
                            console.error(err);
                            res.status(400).send("Não foi possível inserir o usuário !")
                        }
                    });
                }
            } catch (err) {
                console.error(err);
                res.status(400).send("Não foi possível procurar pelo email !");
            }

        });

    } catch (err) {
        return res.status(404).send("Erro ao criptografar senha");
    }
});

//rota de login
app.post("/login", (req, res) => {
    const { email, senha } = req.body;
    const sql = "SELECT email, senha FROM usuarios WHERE email = ? AND status =1"; //query para trazer email e senha

    db.query(sql, [email], async (err, results) => { //verifica se email existe
        if (err) {
            console.error("Erro ao consultar o banco de dados: ", err);
            return res.status(500).send("Erro ao consultar o banco de dados");
        }

        try {
            if (results.length === 0) {//se o array for zero não há usuário com esse email cadastrado
                return res.status(400).send("Email incorreto!");
            }

            const senhaCripto = results[0].senha; //guarda a senha criptografada 

            // Comparando a senha digitada com a senha criptografada do banco de dados
            const senhaCorreta = await bCrypt.compare(senha, senhaCripto); //compara com a senha do formulario e do banco
            if (senhaCorreta) {
                const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: '1h' });
                return res.status(200).json({ message: "Login realizado com sucesso ", token });
            } else {
                return res.status(400).send("Senha incorreta!");
            }

        } catch (error) {
            console.error("Erro ao comparar a senha: ", error);
            res.status(500).send("Erro ao logar");
        }
    });
});

//rota de edição de senha
app.put("/editaSenha", verificarToken, (req, res) => {
    let { email, senha } = req.body; //recebe email e senha
    const procuraUsuario = "SELECT email FROM usuarios WHERE email = ? AND status = 1";
    const mudarSenha = "UPDATE usuarios SET senha = ? WHERE email = ?";
    //verifica se o email existe na base de dados
    db.query(procuraUsuario, [email], async (err, results) => {
        if (err) {
            console.log("Erro ao consultar o banco de dados " + err);
            return res.status(400).send("Erro ao consultar o banco de dados")
        }
        if (results.length === 0) {
            return res.status(400).send("Email incorreto!");
        }

        const senhaCripto = bCrypt.hashSync(senha, 10);// criptografa senha
        //atualiza a senha do usuário 
        db.query(mudarSenha, [senhaCripto, email], async (err, results) => {
            if (err) {
                return res.status(400).send("Não foi possível mudar de senha");
            }
            res.status(200).send("Senha alterada com sucesso !");
        });

    });

});

//rota de edição de nome
app.put("/editaNome", verificarToken, (req, res) => {
    let { email, nome } = req.body; //recebe email e senha
    const procuraUsuario = "SELECT email FROM usuarios WHERE email = ? AND status = 1";
    const mudarNome = "UPDATE usuarios SET senha = ? WHERE email = ?";
    //verifica se o email existe na base de dados
    db.query(procuraUsuario, [email], async (err, results) => {
        if (err) {
            console.log("Erro ao consultar o banco de dados " + err);
            return res.status(400).send("Erro ao consultar o banco de dados")
        }
        if (results.length === 0) {
            return res.status(400).send("Email incorreto!");
        }

        //atualiza o nome do usuário
        db.query(mudarNome, [nome, email], async (err, results) => {
            if (err) {
                return res.status(400).send("Não foi possível mudar de nome");
            }
            res.status(200).send("Nome alterado com sucesso !");
        });

    });
});
//rota de desativar usuario
app.put("/desativaUsuario", verificarToken, (req, res) => {
    let { email } = req.body; //recebe email e senha
    const procuraUsuario = "SELECT email FROM usuarios WHERE email = ?";
    const desativarUsuario = "UPDATE usuarios SET status = ? WHERE email = ?";
    const colunaFalsa = false;
    //verifica se o email existe na base de dados
    db.query(procuraUsuario, [email], async (err, results) => {
        if (err) {
            console.log("Erro ao consultar o banco de dados " + err);
            return res.status(400).send("Erro ao consultar o banco de dados")
        }
        if (results.length === 0) {
            return res.status(400).send("Email incorreto!");
        }

        //atualiza o nome do usuário
        db.query(desativarUsuario, [colunaFalsa, email], async (err, results) => {
            if (err) {
                return res.status(400).send("Não foi possível desativar usuario");
            }
            res.status(200).send("Usuário desativado  !");
        });

    });
});

//rota home
app.get("/home", verificarToken, (req, res) => {
    res.status(200).send("Deu certo voce logou !")
});

// Middleware para verificar o token
function verificarToken(req, res, next) {
    const token = req.headers['authorization']; // O token deve ser enviado no cabeçalho "Authorization"

    if (!token) {
        return res.status(401).send("Acesso negado!"); // Se não houver token, retorna 401
    }

    // Remove o prefixo "Bearer " se estiver presente
    const tokenValido = token.includes('Bearer ') ? token.split(' ')[1] : token;

    jwt.verify(tokenValido, SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).send("Token inválido!"); // Se o token não for válido, retorna 403
        }
        req.user = user; // Salva as informações do usuário na requisição
        next(); // Chama a próxima função (ou rota)
    });
}

//rodando servidor
app.listen(porta, (err, res) => {
    try {
        console.log("SERVIDOR RODANDO NA PORTA " + porta);
    } catch (err) {
        console.error(err)
    }
});