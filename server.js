const express = require('express');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto'); // Importando o módulo crypto
const app = express();
const port = 3000;

// Geração da chave secreta (faça isso apenas uma vez, no início do servidor)
const secretKey = crypto.randomBytes(64).toString('hex');
console.log("Chave secreta gerada:", secretKey); //  NÃO faça commit desta linha em produção!

// Configuração do MySQL (substitua pelas suas credenciais)
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '123456',
    database: 'todo_list',
    port: 3307,
    waitForConnections: true,
    connectionLimit: 10, // Ajuste conforme necessário
    queueLimit: 0 // Para que não haja limite de fila
});

// Testar a conexão com o banco de dados
pool.getConnection()
    .then(connection => {
        console.log('Conectado ao banco de dados MySQL!');
        connection.release(); // liberar a conexão
    })
    .catch(err => {
        console.error('Erro ao conectar ao banco de dados MySQL:', err);
        process.exit(1); // sair do processo se falhar a conexão
    });

app.use(express.static('views')); // Serve arquivos estáticos da pasta 'views'

// Middleware para parsear JSON
app.use(express.json());

// Rota de inicio
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/views/index.html');
});

// Rota de registro de usuário
app.post('/register', async (req, res) => {
    try {
        const { name, email, password, confirmPassword } = req.body;

        // Validações
        if (!name || !email || !password || !confirmPassword) {
            return res.status(400).json({ error: 'Todos os campos são obrigatórios' });
        }
        if (password !== confirmPassword) {
            return res.status(400).json({ error: 'Senhas não coincidem' });
        }

        // Verificar se o email já existe
        const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length > 0) {
            return res.status(400).json({ error: 'Email já cadastrado' });
        }

        // Criptografar a senha
        const salt = bcrypt.genSaltSync(10);
        const hashedPassword = bcrypt.hashSync(password, salt);

        // Inserir o usuário no banco de dados
        await pool.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, hashedPassword]);

        // Obter o ID do usuário recém-inserido
        const [rows2] = await pool.execute('SELECT LAST_INSERT_ID() as id');
        const userId = rows2[0].id;

        // Gerar o JWT
        const token = jwt.sign({ userId: userId }, secretKey, { expiresIn: '1h' });

        res.status(201).json({ message: 'Usuário cadastrado com sucesso', token });
    } catch (error) {
        console.error("Erro ao registrar usuário:", error);
        res.status(500).json({ error: 'Erro ao registrar usuário' });
    }
});

// Rota de login
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validações
        if (!email || !password) {
            return res.status(400).json({ error: 'Email e senha são obrigatórios' });
        }

        // Buscar o usuário no banco de dados
        const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) {
            return res.status(401).json({ error: 'Usuário não encontrado' });
        }

        const user = rows[0];

        // Verificar a senha
        const passwordMatch = bcrypt.compareSync(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Senha incorreta' });
        }

        // Gerar o JWT
        const token = jwt.sign({ userId: user.id }, secretKey, { expiresIn: '1h' });
        res.json({ token });

    } catch (error) {
        console.error("Erro no login:", error);
        res.status(500).json({ error: 'Erro no login' });
    }
});

// Rota protegida para listar tarefas
app.get('/tasks', authenticateJWT, async (req, res) => {
    try {
        const userId = req.user.userId; // Obtém o userId do objeto req.user

        // Consulta SQL para obter as tarefas do usuário
        const [rows] = await pool.execute('SELECT * FROM tasks WHERE userId = ?', [userId]);

        // Retorna as tarefas como resposta
        res.json(rows);
    } catch (error) {
        console.error("Erro ao listar tarefas:", error);
        res.status(500).json({ error: 'Erro ao listar tarefas' });
    }
});

// Rota para criar uma nova tarefa
app.post('/tasks/create', authenticateJWT, async (req, res) => {
    try {
        const { title, description } = req.body;
        const userId = req.user.userId;

        // Validações
        if (!title) {
            return res.status(400).json({ error: 'O título é obrigatório' });
        }

        await pool.execute(
            'INSERT INTO tasks (userId, title, description) VALUES (?, ?, ?)',
            [userId, title, description]
        );

        res.status(201).json({ message: 'Tarefa criada com sucesso' });
    } catch (error) {
        console.error("Erro ao criar tarefa:", error);
        res.status(500).json({ error: 'Erro ao criar tarefa' });
    }
});

// atualizar tarefa
app.put('/tasks/:id', authenticateJWT, async (req, res) => {
    try {
        const taskId = req.params.id;
        const userId = req.user.userId;
        const { title, description, status } = req.body;

        // Validação (adicione mais validações, se necessário)
        if (!taskId || !title) {
            return res.status(400).json({ error: 'ID da tarefa e título são obrigatórios' });
        }

        // Verificar se a tarefa pertence ao usuário
        const [rowsTask] = await pool.execute('SELECT * FROM tasks WHERE id = ? AND userId = ?', [taskId, userId]);
        if(rowsTask.length === 0) {
            return res.status(403).json({error: 'Tarefa não encontrada ou não pertence a este usuário'});
        }

        // Atualizar a tarefa no banco de dados
        await pool.execute(
            'UPDATE tasks SET title = ?, description = ?, status = ? WHERE id = ?',
            [title, description, status, taskId]
        );

        res.json({ message: 'Tarefa atualizada com sucesso' });
    } catch (error) {
        console.error("Erro ao atualizar tarefa:", error);
        res.status(500).json({ error: 'Erro ao atualizar tarefa' });
    }
});

// deletar tarefa
app.delete('/tasks/:id', authenticateJWT, async (req, res) => {
    try {
        const taskId = req.params.id;
        const userId = req.user.userId;

        // Verificar se a tarefa pertence ao usuário
        const [rowsTask] = await pool.execute('SELECT * FROM tasks WHERE id = ? AND userId = ?', [taskId, userId]);
        if(rowsTask.length === 0) {
            return res.status(403).json({error: 'Tarefa não encontrada ou não pertence a este usuário'});
        }

        // Deletar a tarefa no banco de dados
        await pool.execute('DELETE FROM tasks WHERE id = ?', [taskId]);

        res.json({ message: 'Tarefa deletada com sucesso' });
    } catch (error) {
        console.error("Erro ao deletar tarefa:", error);
        res.status(500).json({ error: 'Erro ao deletar tarefa' });
    }
});

// buscar tarefa pelo id
app.get('/tasks/:id', authenticateJWT, async (req, res) => {
    try {
        const taskId = req.params.id;
        const userId = req.user.userId;

        const [rows] = await pool.execute('SELECT * FROM tasks WHERE id = ? AND userId = ?', [taskId, userId]);
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Tarefa não encontrada' });
        }
        res.json(rows[0]); // Retorna apenas um objeto tarefa
    } catch (error) {
        console.error('Erro ao buscar tarefa:', error);
        res.status(500).json({ error: 'Erro ao buscar tarefa' });
    }
});

// Função de autenticação JWT (middleware)
function authenticateJWT(req, res, next) {
    const authHeader = req.headers.authorization;

    if (authHeader) {
        const token = authHeader.split(' ')[1]; // Extrai o token do cabeçalho Authorization: Bearer <token>

        jwt.verify(token, secretKey, (err, user) => {
            if (err) {
                return res.sendStatus(403); // Token inválido
            }

            req.user = user; // Adiciona as informações do usuário à requisição
            next(); // Continua para a próxima função de middleware ou rota
        });
    } else {
        res.sendStatus(401); // Token não fornecido
    }
}

// Trocar de senha
app.put('/users/password', authenticateJWT, async (req, res) => {
    try {
        const userId = req.user.userId;
        const { currentPassword, newPassword, confirmNewPassword } = req.body;

        if (!currentPassword || !newPassword || !confirmNewPassword) {
            return res.status(400).json({ error: 'Todos os campos são obrigatórios' });
        }
        if (newPassword !== confirmNewPassword) {
            return res.status(400).json({ error: 'As novas senhas não coincidem' });
        }

        const [rows] = await pool.execute('SELECT * FROM users WHERE id = ?', [userId]);
        const user = rows[0];

        const passwordMatch = bcrypt.compareSync(currentPassword, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Senha atual incorreta' });
        }

        const salt = bcrypt.genSaltSync(10);
        const hashedNewPassword = bcrypt.hashSync(newPassword, salt);

        await pool.execute('UPDATE users SET password = ? WHERE id = ?', [hashedNewPassword, userId]);

        res.json({ message: 'Senha alterada com sucesso' });
    } catch (error) {
        console.error('Erro ao alterar senha:', error);
        res.status(500).json({ error: 'Erro ao alterar senha' });
    }
});


app.listen(port, () => {
    console.log(`Servidor rodando na porta ${port}`);
});