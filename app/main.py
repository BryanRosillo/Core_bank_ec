import secrets
import logging
from flask import Flask, request, g
from flask_restx import Api, Resource, fields
from functools import wraps
from .db import get_connection, init_db
from .logger import write_log

# Configuración de logs
logging.basicConfig(
    filename="logs/app.log",
    level=logging.DEBUG,
    encoding="utf-8",
    filemode="a",
    format="{asctime} - {levelname} - {message}",
    style="{",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Definición de Flask y Swagger
app = Flask(__name__)
api = Api(
    app,
    version='1.0',
    title='Core Bancario API',
    description='API para operaciones bancarias con autenticación.',
    doc='/swagger'
)

auth_ns = api.namespace('auth', description='Operaciones de autenticación')
bank_ns = api.namespace('bank', description='Operaciones bancarias')

# Middleware para registrar solicitudes entrantes
@app.before_request
def log_request_info():
    write_log("INFO", "Anonymous", f"Solicitud recibida: {request.method} {request.path}", 200)

# ---------------- Autenticación ----------------
@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(api.model('Login', {"username": fields.String(), "password": fields.String()}), validate=True)
    def post(self):
        data = api.payload
        username = data.get("username")
        password = data.get("password")
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, password FROM bank.users WHERE username = %s", (username,))
        user = cur.fetchone()
        if user and user[1] == password:
            token = secrets.token_hex(16)
            cur.execute("INSERT INTO bank.tokens (token, user_id) VALUES (%s, %s)", (token, user[0]))
            conn.commit()
            write_log("INFO", username, "Inicio de sesión exitoso", 200)
            return {"message": "Login successful", "token": token}, 200
        write_log("WARNING", username, "Intento de inicio de sesión fallido", 401)
        return {"message": "Invalid credentials"}, 401

# Decorador para proteger rutas con token

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            write_log("WARNING", "Anonymous", "Acceso no autorizado", 401)
            return {"message": "Unauthorized"}, 401
        token = auth_header.split(" ")[1]
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT u.username FROM bank.tokens t JOIN bank.users u ON t.user_id = u.id WHERE t.token = %s", (token,))
        user = cur.fetchone()
        if not user:
            write_log("WARNING", "Anonymous", "Token inválido o expirado", 401)
            return {"message": "Invalid or expired token"}, 401
        g.user = user[0]
        return f(*args, **kwargs)
    return decorated

# ---------------- Operaciones Bancarias ----------------
@bank_ns.route('/deposit')
class Deposit(Resource):
    @bank_ns.expect(api.model('Deposit', {"account_number": fields.Integer(), "amount": fields.Float()}), validate=True)
    @token_required
    def post(self):
        data = api.payload
        account_number = data.get("account_number")
        amount = data.get("amount")
        if amount <= 0:
            write_log("ERROR", g.user, "Intento de depósito con monto inválido", 400)
            return {"message": "Amount must be greater than zero"}, 400
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("UPDATE bank.accounts SET balance = balance + %s WHERE id = %s RETURNING balance", (amount, account_number))
        result = cur.fetchone()
        if not result:
            write_log("ERROR", g.user, "Intento de depósito en cuenta inexistente", 404)
            return {"message": "Account not found"}, 404
        new_balance = float(result[0])
        conn.commit()
        write_log("INFO", g.user, f"Depósito exitoso de {amount} en cuenta {account_number}", 200)
        return {"message": "Deposit successful", "new_balance": new_balance}, 200

@app.before_first_request
def initialize_db():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
