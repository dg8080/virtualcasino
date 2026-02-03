import os
import io
import base64
import random
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import pbkdf2_sha256
from functools import wraps
from flask_wtf.csrf import CSRFProtect
import pyotp
import qrcode
import json
import re

try:
    from llama_cpp import Llama
    LLAMA_AVAILABLE = True
except ImportError:
    print("Brakuje biblioteki llama-cpp-python!")
    LLAMA_AVAILABLE = False

app = Flask(__name__)
app.secret_key = "3883hdie993"

csrf = CSRFProtect(app)

MODEL_FILENAME = "Qwen3-4B-Instruct-2507-Q4_K_M.gguf"
llm = None

if LLAMA_AVAILABLE:
    if os.path.exists(MODEL_FILENAME):
        print(f"Ładowanie modelu {MODEL_FILENAME}...")
        try:
            llm = Llama(model_path=MODEL_FILENAME, n_ctx=2048, verbose=False)
            print("Model załadowany pomyślnie!")
        except Exception as e:
            print(f"Błąd ładowania modelu: {e}")
    else:
        print(f"Nie znaleziono pliku {MODEL_FILENAME} w folderze aplikacji!")

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///casino.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    balance = db.Column(db.Integer, default=100)
    otp_secret = db.Column(db.String(32))

with app.app_context():
    db.create_all()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Musisz się zalogować.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('base.html')

@app.route('/instruction')
def instruction():
    return render_template('instruction.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$', password):
            flash('Hasło musi mieć co najmniej 8 znaków i zawierać co najmniej jedną małą literę, jedną wielką literę, cyfrę oraz znak specjalny!', 'warning')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash(f'Nazwa {username} jest już zajęta.', 'warning')
            return redirect(url_for('register'))
            
        hashed_password = pbkdf2_sha256.hash(password)
        db.session.add(User(username=username, password_hash=hashed_password))
        db.session.commit()
        flash('Konto utworzone.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and pbkdf2_sha256.verify(request.form['password'], user.password_hash):
            if user.otp_secret:
                session['2fa_user_id'] = user.id
                return redirect(url_for('verify_2fa'))
            session['user_id'] = user.id
            return redirect(url_for('profile'))
        flash('Błąd logowania.', 'danger')
    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if '2fa_user_id' not in session: return redirect(url_for('login'))
    if request.method == 'POST':
        user = User.query.get(session['2fa_user_id'])
        if pyotp.TOTP(user.otp_secret).verify(request.form['token']):
            session.pop('2fa_user_id', None)
            session['user_id'] = user.id
            return redirect(url_for('profile'))
        flash('Zły kod.', 'danger')
    return render_template('verify_2fa.html')

@app.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        secret = request.form['secret']
        if pyotp.TOTP(secret).verify(request.form['token']):
            user.otp_secret = secret
            db.session.commit()
            return redirect(url_for('profile'))
        flash('Zły kod.', 'danger')
    secret = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user.username, issuer_name="Wirtualne Kasyno")
    img = qrcode.make(uri)
    buf = io.BytesIO(); img.save(buf); buf.seek(0)
    return render_template('setup_2fa.html', secret=secret, qr_b64=base64.b64encode(buf.getvalue()).decode('ascii'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=User.query.get(session['user_id']))

@app.route('/bliczek', methods=['GET', 'POST'])
@login_required
def bliczek():
    user=User.query.get(session['user_id'])
    if request.method == 'POST':
        code = request.form['code']
        if re.match("[0-9][0-9][0-9][0-9][0-9][0-9]", code):
            user.balance += 100
            db.session.commit()
            flash('Pomyślnie doładowano konto.', 'info')
        else:
            flash('Nieprawidłowy kod.', 'warning')
            return redirect(url_for('bliczek'))
    return render_template('bliczek.html', user=user)

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/play', methods=['GET', 'POST'])
@login_required
def play():
    user = User.query.get(session['user_id'])
    result_msg = None
    slot_1 = "seven"
    slot_2 = "seven"
    slot_3 = "seven"
    if request.method == 'POST':
        bet = int(request.form['bet'])
        if bet > user.balance: flash('Brak środków', 'danger')
        else:
            slot_figures = ["seven", "cherry", "lemon", "diamont", "apple", "orange", "bell"]
            slot_1 = slot_figures[random.randint(0, 6)]
            slot_2 = slot_figures[random.randint(0, 6)]
            slot_3 = slot_figures[random.randint(0, 6)]
            win = (slot_1 == slot_2) and (slot_1 == slot_3)
            if win:
                if slot_1 == "seven": user.balance += 10*bet; result_msg = "WIELKA WYGRANA!"
                else: user.balance += bet; result_msg = "WYGRANA!"
            else: user.balance -= bet; result_msg = "PRZEGRANA."
            db.session.commit()
    return render_template('play.html', user=user, result=result_msg, slot_1=slot_1, slot_2=slot_2, slot_3=slot_3)

def get_deck():
    suits = ['♠', '♥', '♦', '♣']
    ranks = ['2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K', 'A']
    return [f"{r}{s}" for s in suits for r in ranks]

def calculate_value(hand):
    value = 0
    aces = 0
    for card in hand:
        rank = card[:-1]
        if rank in ['J', 'Q', 'K']:
            value += 10
        elif rank == 'A':
            aces += 1
        else:
            value += int(rank)
    
    for _ in range(aces):
        if value + 11 <= 21:
            value += 11
        else:
            value += 1
    return value

@app.route('/play-ai', methods=['GET', 'POST'])
@login_required
def play_ai():
    user = User.query.get(session['user_id'])
    ai_comment = "Witaj! W co gramy? Blackjack czy kości?"
    game_result = None

    if request.method == 'POST':
        user_input = request.form.get('user_input', '').lower()
        
        tools_definition = [
            {"type": "function", "function": {
                "name": "start_blackjack", 
                "description": "Start gry w karty", 
                "parameters": {
                    "type": "object", 
                    "properties": {
                        "bet": {"type": "integer"}
                    }, 
                    "required": ["bet"]}}},
            {"type": "function", "function": {"name": "hit", 
                "description": "Dobieranie karty. Wywołaj, gdy gracz mówi, że chce kolejną kartę, przykładowo: "
                    "'poproszę kartę', 'jeszcze jedna karta', 'dobieram', 'dobierz', 'chcę dobrać', 'dobieram kartę', 'hit'.", 
                "parameters": {"type": "object", "properties": {}}}},
            {"type": "function", "function": {"name": "stand", 
                "description": "Gracz pasuje, brak dobierania kart. Wywołaj, gdy gracz mówi, "
                    "że nie chce więcej kart, przykładowo: 'pas', 'pasuję', 'nie dobieram', 'nie dobieram karty', 'pass', 'stand'.", 
                "parameters": {"type": "object", "properties": {}}}},
            {"type": "function", "function": {
                "name": "roll_dice", 
                "description": "Rzut kością", 
                "parameters": {
                    "type": "object", 
                    "properties": {
                        "sides": {"type": "integer"},
                        "bet": {"type": "integer"},
                        "prediction": {"type": "string", "enum": ["parzyste", "nieparzyste"]}
                    },
                    "required": ["sides", "bet"]
                }
            }}
        ]

        if llm and user_input:
            try:
                output = llm.create_chat_completion(
                    messages=[
                        {"role": "system", "content": "Jesteś sarkastycznym krupierem w kasynie. Obsługuj gry używając <tool_call>. Odpowiadaj jako krupier krótko."},
                        {"role": "user", "content": user_input}
                    ],
                    tools=tools_definition
                )

                response_content = output['choices'][0]['message']['content']
                tool_call_data = None

                if "<tool_call>" in response_content:
                    match = re.search(r'<tool_call>(.*?)</tool_call>', response_content, re.DOTALL)
                    if match: tool_call_data = json.loads(match.group(1))
                elif "tool_calls" in output['choices'][0]['message']:
                    tc = output['choices'][0]['message']['tool_calls'][0]['function']
                    tool_call_data = {"name": tc['name'], "arguments": json.loads(tc['arguments'])}

                internal_info = ""
                
                if tool_call_data:
                    func_name = tool_call_data.get('name')
                    args = tool_call_data.get('arguments', {})
                    print(args)

                    if func_name == "roll_dice":
                        bet = args.get('bet', 0)
                        if bet > user.balance:
                            internal_info = "Nie udzielamy kredytów."
                        elif bet <= 0: internal_info = "Podaj stawkę, za jaką chcesz grać."                        
                        elif bet > 0:
                            sides = args.get('sides', 6)
                            prediction = args.get('prediction')
                            roll = random.randint(1, sides)
                            win = (prediction == "parzyste" and roll % 2 == 0) or (prediction == "nieparzyste" and roll % 2 != 0)
                            if win:
                                user.balance += bet
                                internal_info = f"WYGRANA! Wypadło {roll} ({prediction})."
                            else:
                                user.balance -= bet
                                internal_info = f"PRZEGRANA. Wypadło {roll} (to nie jest {prediction})."
                            db.session.commit()
                        else:
                            internal_info = f"Rzut: wypadło {roll}."
                        game_result = internal_info

                    elif func_name == "start_blackjack":
                        bet = args.get('bet', 0)
                        if bet > user.balance: internal_info = "Nie udzielamy kredytów."
                        elif bet <= 0: internal_info = "Podaj stawkę, za jaką chcesz grać."
                        else:
                            deck = get_deck()
                            random.shuffle(deck)
                            p_hand, d_hand = [deck.pop(), deck.pop()], [deck.pop(), deck.pop()]
                            session.update({'bj_deck': deck, 'bj_player': p_hand, 'bj_dealer': d_hand, 'bj_bet': bet})
                            val = calculate_value(p_hand)
                            if val == 21:
                                user.balance += 2*session['bj_bet']
                                internal_info = f"BLACKJACK! Twoja ręka: {p_hand[0]} i {p_hand[1]}."
                                db.session.commit()
                                session.pop('bj_deck', None)
                                session.pop('bj_deck', None)
                                session.pop('bj_player', None)
                                session.pop('bj_dealer', None)
                                session.pop('bj_bet', None)
                            else:    
                                internal_info = f"Karty na stole. Twoja ręka: {p_hand[0]} i {p_hand[1]}. Twoja suma: {calculate_value(p_hand)}. Krupier pokazuje {d_hand[0]}. Co robisz?"
                        game_result = internal_info

                    elif func_name == "hit":
                        deck, p_hand = session.get('bj_deck'), session.get('bj_player')
                        if deck and p_hand:
                            new_card = deck.pop()
                            p_hand.append(new_card)
                            val = calculate_value(p_hand)
                            session['bj_player'] = p_hand
                            if val > 21:
                                user.balance -= session['bj_bet']
                                internal_info = f"FURA! Dobrałeś kartę {new_card} i masz {val}. Przegrałeś zakład."
                                db.session.commit()
                                session.pop('bj_deck', None)
                                session.pop('bj_deck', None)
                                session.pop('bj_player', None)
                                session.pop('bj_dealer', None)
                                session.pop('bj_bet', None)
                            else:
                                internal_info = f"Dobrałeś kartę {new_card}. Masz {val}. Kolejna czy pas?"
                        game_result = internal_info

                    elif func_name == "stand":
                        deck, p_hand, d_hand = session.get('bj_deck'), session.get('bj_player'), session.get('bj_dealer')
                        if deck and p_hand:
                            p_v, d_v = calculate_value(p_hand), calculate_value(d_hand)
                            while d_v < 17:
                                d_hand.append(deck.pop())
                                d_v = calculate_value(d_hand)
                            
                            if d_v > 21 or p_v > d_v:
                                user.balance += session['bj_bet']
                                internal_info = f"WYGRANA! Ty: {p_v}, Krupier: {d_v}. Gratulacje!"
                            elif d_v > p_v:
                                user.balance -= session['bj_bet']
                                internal_info = f"PRZEGRANA. Ty: {p_v}, Krupier: {d_v}."
                            else: internal_info = f"REMIS przy {p_v}."
                            
                            db.session.commit()
                            session.pop('bj_deck', None)
                            session.pop('bj_player', None)
                            session.pop('bj_dealer', None)
                            session.pop('bj_bet', None)
                        game_result = internal_info

                    final_resp = llm.create_chat_completion(
                        messages=[
                            {"role": "system", "content": "Jesteś sarkastycznym krupierem. Odpowiadaj jako krupier krótko."},
                            {"role": "user", "content": f"Akcja zakończona: {internal_info}"}
                        ]
                    )
                    ai_comment = final_resp['choices'][0]['message']['content']
                else:
                    ai_comment = response_content

            except Exception as e:
                print(f"Błąd: {e}")
                ai_comment = "Wybacz, muszę przetasować karty... spróbuj za chwilę."

    return render_template('play_ai.html', user=user, ai_comment=ai_comment, game_result=game_result)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)