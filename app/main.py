import secrets
import logging
from flask import Flask, request, g
from flask_restx import Api, Resource, fields
from functools import wraps
from .db import get_connection, init_db
from .logger import write_log
import logging
import os
import jwt
import datetime
import json
import random
import time
from tempfile import NamedTemporaryFile

SECRET_KEY = os.getenv("SECRET_KEY", "clave_secreta_por_defecto")
blacklisted_tokens = set()

# Path to save OTPs
OTP_DIRECTORY = 'tmp_otps/'
os.makedirs(OTP_DIRECTORY, exist_ok=True)

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


# Define the expected payload models for Swagger

login_model = auth_ns.model('Login', {
    'username': fields.String(required=True, description='Nombre de usuario', example='user1'),
    'password': fields.String(required=True, description='Contraseña', example='pass1')
})
# Ejemplo de petición:
# curl -X POST "http://localhost:5000/login" -H "Content-Type: application/json" -d '{"username": "user1", "password": "pass1"}'

otp_model = auth_ns.model('OTP', {
    'message': fields.String(required=True, description='Mensaje de respuesta'),
    'OTP': fields.String(required=True, description='OTP generado'),
})

deposit_model = bank_ns.model('Deposit', {
    'account_number': fields.Integer(required=True, description='Número de cuenta', example=123),
    'amount': fields.Float(required=True, description='Monto a depositar', example=100)
})
# Ejemplo de petición:
# curl -X POST "http://localhost:5000/deposit" -H "Content-Type: application/json" -d '{"account_number": 123, "amount": 100}'

withdraw_model = bank_ns.model('Withdraw', {
    'amount': fields.Float(required=True, description='Monto a retirar', example=100)
})
# Ejemplo de petición:
# curl -X POST "http://localhost:5000/withdraw" -H "Content-Type: application/json" -d '{"amount": 100}'

transfer_model = bank_ns.model('Transfer', {
    'target_username': fields.String(required=True, description='Usuario destino', example='user2'),
    'amount': fields.Float(required=True, description='Monto a transferir', example=100),
    'otp': fields.String(required=True, description='OTP', example='123456')
})
# Ejemplo de petición:
# curl -X POST "http://localhost:5000/transfer" -H "Content-Type: application/json" -d '{"target_username": "user2", "amount": 100, "otp": "123456"}'

credit_payment_model = bank_ns.model('CreditPayment', {
    'amount': fields.Float(required=True, description='Monto de la compra a crédito', example=100)
})
# Ejemplo de petición:
# curl -X POST "http://localhost:5000/credit-payment" -H "Content-Type: application/json" -d '{"amount": 100}'

pay_credit_balance_model = bank_ns.model('PayCreditBalance', {
    'amount': fields.Float(required=True, description='Monto a abonar a la deuda de la tarjeta', example=50)
})
# Ejemplo de petición:
# curl -X POST "http://localhost:5000/pay-credit-balance" -H "Content-Type: application/json" -d '{"amount": 50}'



# Middleware para registrar solicitudes entrantes
@app.before_request
def log_request_info():
    write_log("INFO", "Anonymous", f"Solicitud recibida: {request.method} {request.path}", 200)
    

# ---------------- Authentication Endpoints ----------------
# Función para generar el token JWT
def generate_jwt(user_id, username, role):
    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Expira en 1 hora
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "exp": expiration
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


# Función para validar el token JWT
def verify_jwt(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload  # Devuelve la información del usuario
    except jwt.ExpiredSignatureError:
        api.abort(401, "Token expirado")
    except jwt.InvalidTokenError:
        api.abort(401, "Token inválido")
    

# ---------------- Token-Required Decorator ----------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            api.abort(401, "Authorization header missing or invalid")
        token = auth_header.split(" ")[1]

        if token in blacklisted_tokens:
            api.abort(401, "Token invalidado")
        
        payload = verify_jwt(token)  # Verifica el JWT
        g.user = {
            "id": payload["user_id"],
            "username": payload["username"],
            "role": payload["role"]
        }
        return f(*args, **kwargs)
    return decorated

# ---------------- OTP Endpoint ----------------
# OTP is saved in a file. We can choose to use another option. 
# OTP has 6 digits, and a time life of 5 min. 
@auth_ns.route('/generate-otp')
class GenerateOTP(Resource):
    @token_required
    def post(self):
        try:
            """Genera un OTP de 6 dígitos y 5 min de vida, necesario para hacer transferencias."""
            otp = str(random.randint(100000, 999999))
            otp_data = {
                "otp": otp,
                "expires_at": time.time() + 300
            }

            otp_filename = os.path.join(OTP_DIRECTORY, f"{g.user['id']}_otp.json")
            with open(otp_filename, 'w') as f:
                json.dump(otp_data, f)

            write_log("INFO", g.user['username'], f"OTP generado para el usuario {g.user['username']}", 200)

            return {"message": "OTP created", "OTP": otp}, 200
        except Exception as e:
            write_log("ERROR", g.user['username'], f"Error al generar OTP: {str(e)}", 500)
            api.abort(500, "Error al generar OTP")


# ---------------- Authentication Endpoints ----------------
@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(api.model('Login', {"username": fields.String(), "password": fields.String()}), validate=True)
    def post(self):
        data = api.payload
        username = data.get("username")
        password = data.get("password")
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, username, password, role FROM bank.users WHERE username = %s", (username,))
        user = cur.fetchone()

        cur.close()
        conn.close()
        
        if user and user[2] == password:
            token = generate_jwt(user[0], user[1], user[3])
            write_log("INFO", username, "Inicio de sesión exitoso", 200)
            return {"message": "Login exitoso", "token": token}, 200
        else:
            write_log("WARNING", username, "Intento de inicio de sesión fallido", 401)
            api.abort(401, "Credenciales inválidas")    

@auth_ns.route('/logout')
class Logout(Resource):
    @auth_ns.doc('logout')
    @token_required  # Se requiere el token en el logout para poder invalidarlo
    def post(self):
        """Cierra sesión invalidando el token actual."""
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.split(" ")[1]
        # Se añade el token a lista negra para invalidarlo en caso de que no expire todavía
        blacklisted_tokens.add(token)
        write_log("INFO", g.user['username'], "Cierre de sesión exitoso", 200)
        return {"message": "Logout exitoso."}, 200
    

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
            write_log("ERROR", g.user['username'], "Intento de depósito en cuenta inexistente", 404)
            return {"message": "Account not found"}, 404
        new_balance = float(result[0])
        conn.commit()
        write_log("INFO", g.user['username'], f"Depósito exitoso de {amount} en cuenta {account_number}", 200)
        return {"message": "Deposit successful", "new_balance": new_balance}, 200
    

@bank_ns.route('/withdraw')
class Withdraw(Resource):
    @bank_ns.expect(withdraw_model, validate=True)
    @bank_ns.doc('withdraw')
    @token_required
    def post(self):
        """Realiza un retiro de la cuenta del usuario autenticado."""
        data = api.payload
        amount = data.get("amount", 0)
        if amount <= 0:
            api.abort(400, "Amount must be greater than zero")
        user_id = g.user['id']
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            write_log("ERROR", g.user['username'], "Cuenta no encontrada", 404)
            cur.close()
            conn.close()
            api.abort(404, "Account not found")
        current_balance = float(row[0])
        if current_balance < amount:
            write_log("WARNING", g.user['username'], "Fondos insuficientes para retiro", 400)
            cur.close()
            conn.close()
            api.abort(400, "Insufficient funds")
        try:
            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s RETURNING balance", (amount, user_id))
            new_balance = float(cur.fetchone()[0])
            conn.commit()
            write_log("INFO", g.user['username'], f"Retiro exitoso de {amount}. Nuevo saldo: {new_balance}", 200)
            return {"message": "Withdrawal successful", "new_balance": new_balance}, 200
        except Exception as e:
            write_log("ERROR", g.user['username'], f"Error durante el retiro: {str(e)}", 500)
            conn.rollback()
            cur.close()
            conn.close()
            api.abort(500, "Error durante el retiro")
    

@bank_ns.route('/transfer')
class Transfer(Resource):
    @bank_ns.expect(transfer_model, validate=True)
    @bank_ns.doc('transfer')
    @token_required
    def post(self):
        """Transfiere fondos desde la cuenta del usuario autenticado a otra cuenta."""
        data = api.payload
        target_username = data.get("target_username")
        amount = data.get("amount", 0)
        otp = data.get("otp")
        
        if not target_username or amount <= 0 or not otp:
            write_log("ERROR", g.user['username'], "Datos inválidos para transferencia", 400)
            api.abort(400, "Invalid data")
        if target_username == g.user['username']:
            write_log("ERROR", g.user['username'], "Intento de transferencia a la misma cuenta", 400)
            api.abort(400, "Cannot transfer to the same account")
        
        # OTP is checked
        otp_filename = os.path.join(OTP_DIRECTORY, f"{g.user['id']}_otp.json")
        if not os.path.exists(otp_filename):
            write_log("ERROR", g.user['username'], "OTP no encontrado", 400)
            api.abort(400, "No OTP found, please generate a new one")
        with open(otp_filename, 'r') as f:
            otp_data = json.load(f)
        if time.time() > otp_data["expires_at"]:
            os.remove(otp_filename)
            write_log("ERROR", g.user['username'], "OTP expirado", 400)
            api.abort(400, "OTP expired")
        if otp_data["otp"] != otp:
            os.remove(otp_filename)
            write_log("ERROR", g.user['username'], "OTP inválido", 400)
            api.abort(400, "Invalid OTP")
        os.remove(otp_filename)

        conn = get_connection()
        cur = conn.cursor()
        # Check sender's balance
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.user['id'],))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            write_log("ERROR", g.user['username'], "Cuenta del remitente no encontrada", 404)
            api.abort(404, "Sender account not found")
        sender_balance = float(row[0])
        if sender_balance < amount:
            write_log("WARNING", g.user['username'], "Fondos insuficientes para transferencia", 400)
            cur.close()
            conn.close()
            api.abort(400, "Insufficient funds")
        # Find target user
        cur.execute("SELECT id FROM bank.users WHERE username = %s", (target_username,))
        target_user = cur.fetchone()
        if not target_user:
            write_log("ERROR", g.user['username'], "Usuario destino no encontrado", 404)
            cur.close()
            conn.close()
            api.abort(404, "Target user not found")
        target_user_id = target_user[0]
        try:
            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", (amount, g.user['id']))
            cur.execute("UPDATE bank.accounts SET balance = balance + %s WHERE user_id = %s", (amount, target_user_id))
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.user['id'],))
            new_balance = float(cur.fetchone()[0])
            conn.commit()
        except Exception as e:
            conn.rollback()
            cur.close()
            conn.close()
            write_log("ERROR", g.user['username'], f"Error durante la transferencia: {str(e)}", 500)
            api.abort(500, f"Error during transfer: {str(e)}")
        cur.close()
        conn.close()
        write_log("INFO", g.user['username'],
                  f"Transferencia exitosa de {amount} a {target_username}. Nuevo saldo: {new_balance}", 200)
        return {"message": "Transfer successful", "new_balance": new_balance}, 200
    

@bank_ns.route('/credit-payment')
class CreditPayment(Resource):
    @bank_ns.expect(credit_payment_model, validate=True)
    @bank_ns.doc('credit_payment')
    @token_required
    def post(self):
        """
        Realiza una compra a crédito:
        - Descuenta el monto de la cuenta.
        - Aumenta la deuda de la tarjeta de crédito.
        """
        data = api.payload
        amount = data.get("amount", 0)
        if amount <= 0:
            write_log("ERROR", g.user['username'], "Monto inválido para pago de crédito", 400)
            api.abort(400, "Amount must be greater than zero")
        user_id = g.user['id']
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            write_log("ERROR", g.user['username'], "Cuenta no encontrada", 404)
            api.abort(404, "Account not found")
        account_balance = float(row[0])
        if account_balance < amount:
            cur.close()
            conn.close()
            write_log("WARNING", g.user['username'], "Fondos insuficientes para pago de crédito", 400)
            api.abort(400, "Insufficient funds in account")
        try:
            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", (amount, user_id))
            cur.execute("UPDATE bank.credit_cards SET balance = balance + %s WHERE user_id = %s", (amount, user_id))
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
            new_account_balance = float(cur.fetchone()[0])
            cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
            new_credit_balance = float(cur.fetchone()[0])
            conn.commit()
        except Exception as e:
            conn.rollback()
            cur.close()
            conn.close()
            write_log("ERROR", g.user['username'], f"Error durante el pago de crédito: {str(e)}", 500)
            api.abort(500, f"Error processing credit card purchase: {str(e)}")
        cur.close()
        conn.close()
        write_log("INFO", g.user['username'],
                  f"Pago de crédito exitoso. Nuevo saldo: {new_account_balance}, Deuda: {new_credit_balance}", 200)
        return {
            "message": "Credit card purchase successful",
            "account_balance": new_account_balance,
            "credit_card_debt": new_credit_balance
        }, 200
    

@bank_ns.route('/pay-credit-balance')
class PayCreditBalance(Resource):
    @bank_ns.expect(pay_credit_balance_model, validate=True)
    @bank_ns.doc('pay_credit_balance')
    @token_required
    def post(self):
        """
        Realiza un abono a la deuda de la tarjeta:
        - Descuenta el monto (o el máximo posible) de la cuenta.
        - Reduce la deuda de la tarjeta de crédito.
        """
        data = api.payload
        amount = data.get("amount", 0)
        if amount <= 0:
            write_log("ERROR", g.user['username'], "Monto inválido para pago de saldo de crédito", 400)
            api.abort(400, "Amount must be greater than zero")
        user_id = g.user['id']
        conn = get_connection()
        cur = conn.cursor()
        # Check account funds
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            write_log("ERROR", g.user['username'], "Cuenta no encontrada", 404)
            api.abort(404, "Account not found")
        account_balance = float(row[0])
        if account_balance < amount:
            cur.close()
            conn.close()
            write_log("WARNING", g.user['username'], "Fondos insuficientes para pago de saldo de crédito", 400)
            api.abort(400, "Insufficient funds in account")
        # Get current credit card debt
        cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            conn.close()
            write_log("ERROR", g.user['username'], "Tarjeta de crédito no encontrada", 404)
            api.abort(404, "Credit card not found")
        credit_debt = float(row[0])
        payment = min(amount, credit_debt)
        try:
            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", (payment, user_id))
            cur.execute("UPDATE bank.credit_cards SET balance = balance - %s WHERE user_id = %s", (payment, user_id))
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
            new_account_balance = float(cur.fetchone()[0])
            cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
            new_credit_debt = float(cur.fetchone()[0])
            conn.commit()
        except Exception as e:
            conn.rollback()
            cur.close()
            conn.close()
            write_log("ERROR", g.user['username'], f"Error durante el pago de saldo de crédito: {str(e)}", 500)
            api.abort(500, f"Error processing credit balance payment: {str(e)}")
        cur.close()
        conn.close()
        write_log("INFO", g.user['username'],
                  f"Pago de saldo de crédito exitoso. Nuevo saldo: {new_account_balance}, Deuda restante: {new_credit_debt}",
                  200)
        return {
            "message": "Credit card debt payment successful",
            "account_balance": new_account_balance,
            "credit_card_debt": new_credit_debt
        }, 200


@app.before_first_request
def initialize_db():
    try:
        init_db()
        write_log("INFO", "System", "Base de datos inicializada correctamente", 200)
    except Exception as e:
        write_log("ERROR", "System", f"Error al inicializar la base de datos: {str(e)}", 500)

@app.errorhandler(Exception)
def handle_exception(e):
    write_log("ERROR", "System", f"Error no capturado: {str(e)}", 500)
    return {"message": "Internal Server Error"}, 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
