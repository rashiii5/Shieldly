from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import sqlite3
from urllib.parse import urlparse, unquote
import re
import idna
from PIL import Image
import io

app = Flask(__name__)
app.secret_key = 'supersecretkey'

DB_FILE = 'shieldly.db'

SUSPICIOUS_TLDS = ['.xyz', '.ru', '.top', '.tk', '.cn']
TRAP_KEYWORDS = ['login', 'secure', 'verify', 'bank', 'update', 'free', 'confirm']
ENCODED_PATTERN = re.compile(r'%[0-9a-fA-F]{2}')

TIP_OF_THE_DAY = [
    "Always hover over a link to see the actual destination before clicking.",
    "Avoid clicking links from unknown or suspicious email senders.",
    "Shortened links can hide dangerous destinations. Use a URL expander first.",
    "Be wary of urgent messages urging you to 'verify your account' quickly.",
    "Look for spelling errors in domain names like go0gle.com or paypa1.com."
]

# Function to create and connect to the database
def create_connection():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Create user table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )''')

    # Create questions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS questions (
            id INTEGER PRIMARY KEY,
            question TEXT NOT NULL,
            option1 TEXT NOT NULL,
            option2 TEXT NOT NULL,
            option3 TEXT NOT NULL,
            score1 INTEGER NOT NULL,
            score2 INTEGER NOT NULL,
            score3 INTEGER NOT NULL
        )''')

    conn.commit()

    # List of questions and options with scores
    questions_data = [
        ("Do you reuse the same password for multiple accounts?",
         "Never", "Sometimes", "Always", 5, 3, 0),

        ("Do you use a password manager?",
         "Yes, always", "Occasionally", "Never", 5, 3, 0),

        ("Are your passwords typically 12 characters or longer and contain symbols/numbers?",
         "Always", "Sometimes", "Rarely or Never", 5, 3, 0),

        ("Do you use two-factor authentication (2FA) on important accounts (email, banking, social media)?",
         "Yes, on all", "Only on a few", "Not at all", 5, 3, 0),

        ("Do you leave your devices (laptop/phone) unlocked in public or shared spaces?",
         "Never", "Sometimes", "Often", 5, 3, 0),

        ("Do you share your passwords or PINs with friends/family?",
         "No, never", "Rarely", "Yes", 5, 3, 0),

        ("Is your main social media profile public?",
         "No, it’s private", "Some parts are public", "Entirely public", 5, 3, 0),

        ("Do you post real-time updates (e.g., location, travel plans, check-ins)?",
         "Never", "Sometimes", "Frequently", 5, 3, 0),

        ("Do you list your birthdate, phone number, email, or home address on social media?",
         "None of these", "Only birthdate", "Two or more", 5, 3, 0),

        ("Do you share personal milestones (graduation, relationship status, job changes) online?",
         "Rarely or never", "Occasionally", "Frequently", 5, 3, 0),

        ("Have you ever reviewed or updated your privacy settings on social media or apps?",
         "Yes, regularly", "Once or twice", "Never", 5, 3, 0),

        ("Do you read permission prompts before granting access to apps (like microphone, camera, contacts)?",
         "Always", "Sometimes", "Rarely or never", 5, 3, 0),

        ("Do you regularly check your account activity and login history (e.g., Google, Facebook)?",
         "Yes", "Occasionally", "No", 5, 3, 0),

        ("Do you share photos with identifiable info (school logos, license plates, background locations)?",
         "Never", "Occasionally", "Often", 5, 3, 0),

        ("Do you take online quizzes or use personality filter apps that ask for access to your data?",
         "Never", "Rarely", "Frequently", 5, 3, 0),

        ("Do you give your real phone number or email when signing up for free trials or newsletters?",
         "No, I use a throwaway", "Sometimes", "Always", 5, 3, 0),

        ("Do you connect to public Wi-Fi without using a VPN?",
         "Never", "Sometimes", "Always", 5, 3, 0),

        ("Have you ever checked if your email has been part of a data breach (e.g., HaveIBeenPwned)?",
         "Yes", "I’ve heard of it but haven’t used it", "What’s that?", 5, 3, 0),

        ("Do you use different emails for work, personal, and subscriptions?",
         "Yes", "Only 2 types", "Same for everything", 5, 3, 0),

        ("Do you regularly update software, browsers, and antivirus programs?",
         "Yes, auto-updates enabled", "I update manually sometimes", "I often forget", 5, 3, 0)
    ]
    
    '''
    # Insert data into the table
    cursor.executemany('INSERT INTO questions (question, option1, option2, option3, score1, score2, score3) VALUES (?, ?, ?, ?, ?, ?, ?)', questions_data)
    '''
    
    conn.commit()

    return conn

# Function to create a new user
def create(username, password):
    query = "INSERT INTO user VALUES (?, ?)"
    print(query)
    conn = create_connection()
    cur = conn.cursor()
    cur.execute(query, (username, password))
    conn.commit()
    conn.close()

# Function to find a user by username
def find_by_username(username):
    query = "SELECT username, password FROM user WHERE username = ?"
    conn = create_connection()
    cur = conn.cursor()
    cur.execute(query, (username,))
    row = cur.fetchone()
    conn.close()

    if row:
        return {'username': row[0], 'password': row[1]}
    else:
        return None

# Function to get a database connection
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# Check Password
def is_strong_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    has_upper = has_special = has_lower = has_digit = False
    special_characters = set("!@#$%^&*(),.?\":{}|<>")

    for char in password:
        if char.isupper():
            has_upper = True
        elif char.islower():
            has_lower = True
        elif char.isdigit():
            has_digit = True
        elif char in special_characters:
            has_special = True

    if not has_upper:
        return False, "Password must contain at least one uppercase letter"
    if not has_lower:
        return False, "Password must contain at least one lowercase letter"
    if not has_digit:
        return False, "Password must contain at least one digit"
    if not has_special:
        return False, "Password must contain at least one special character"
    
    return True, "Password is strong"

@app.route('/')
def index():
    create_connection()
    return render_template('index.html')

# Login route and logic
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        print(f"Received login request with username: {username} and password: {password}")

        user = find_by_username(username)

        if user:
            print(f"User found in database: {user}")
            if user['password'] == password:
                session['username'] = username
                print("Login successful!")
                return redirect(url_for('quiz_main'))
            else:
                print("Incorrect password")
        else:
            print("User not found")

        error_message = 'Invalid username or password'
        return render_template('login.html', error_message=error_message)
    else:
        return render_template('login.html')

# User creation route and logic
@app.route('/create_user', methods=['GET', 'POST'])
def create_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if find_by_username(username):
            error_message = 'Username already exists'
            return render_template('create_user.html', error_message=error_message)
        
        checkpassword,error_message=is_strong_password(password)
        if not checkpassword:
            return render_template('create_user.html', error_message=error_message)
        
        create(username, password)
        return redirect(url_for('login'))
    return render_template('create_user.html')

# Quiz main page route and logic
@app.route('/quiz_main')
def quiz_main():
    return render_template('quiz_main.html')

# Route to start the quiz
@app.route('/quiz')
def quiz():
    conn = get_db_connection()
    questions = conn.execute('SELECT * FROM questions').fetchall()
    conn.close()

    # Store questions in session as list of dicts
    session['questions'] = [dict(q) for q in questions]
    session['current_question'] = 0
    session['score'] = 0

    # Start with the first question
    return render_template('quiz.html', question=session['questions'][0])

# Route to handle each question response
@app.route('/next_question', methods=['POST'])
def next_question():
    selected_option = request.form.get('option')
    current_question_index = session['current_question']
    questions = session['questions']

    # Get score from selected option
    if selected_option == 'option1':
        session['score'] += questions[current_question_index]['score1']
    elif selected_option == 'option2':
        session['score'] += questions[current_question_index]['score2']
    elif selected_option == 'option3':
        session['score'] += questions[current_question_index]['score3']

    # Move to next question
    session['current_question'] += 1

    # If no more questions, show result
    if session['current_question'] >= len(questions):
        return redirect(url_for('quiz_result'))

    # Otherwise, show next question
    return render_template(
        'quiz.html',
        question=questions[session['current_question']]
    )

# Route to display quiz result
@app.route('/quiz_result')
def quiz_result():
    score = session.get('score')
    total_questions = len(session.get('questions'))

    session.pop('current_question', None)
    session.pop('score', None)
    session.pop('questions', None)

    return render_template('quiz_result.html', score=score, total_questions=total_questions)

# Analyse URL
def check_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path + parsed.query
    reasons = []

    # Unicode/IDN spoofing check
    try:
        ascii_domain = idna.decode(domain)
    except:
        ascii_domain = domain
        reasons.append({
            "title": "❌ Spoofed or Invalid Characters in Domain",
            "details": "This domain contains non-standard or misleading Unicode characters that may be used in homograph attacks."
        })

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            reasons.append({
                "title": f"⚠️ Suspicious TLD: `{tld}`",
                "details": f"Domains ending with `{tld}` are often associated with phishing or low-trust websites. Avoid unless verified."
            })
            break

    # Numeric-heavy or IP address domains
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain) or len(re.findall(r'\d', domain)) > 5:
        reasons.append({
            "title": "⚠️ Numeric or IP-Based Domain",
            "details": "Domains with excessive numbers or IP formats may be trying to bypass detection systems. These are often suspicious."
        })

    # Phishing keywords in path
    for keyword in TRAP_KEYWORDS:
        if keyword in path.lower():
            reasons.append({
                "title": f"⚠️ Keyword Trap Detected: `{keyword}`",
                "details": "The link contains phishing-related terms such as 'login', 'verify', or 'update', commonly used to trick users."
            })
            break

    # Double encoding / Obfuscation
    if ENCODED_PATTERN.findall(unquote(unquote(url))):
        reasons.append({
            "title": "⚠️ Obfuscated or Encoded URL",
            "details": "The URL is encoded multiple times. Attackers use this to hide true destinations from both users and scanners."
        })

    # Use of '@' symbol
    if '@' in domain:
        reasons.append({
            "title": "❌ '@' Symbol Found in URL",
            "details": "Attackers can place fake domains before '@' to mislead users. The browser will navigate to the part after '@'."
        })

    return {
        "parsed": parsed,
        "domain": ascii_domain,
        "path": path,
        "reasons": reasons,
        "tip": TIP_OF_THE_DAY[hash(url) % len(TIP_OF_THE_DAY)],
        "clean_url": f"{parsed.scheme}://{parsed.netloc}{parsed.path}"  # optional cleaned display
    }

@app.route('/suslink', methods=['GET', 'POST'])
def suslink():
    result = None
    if request.method == 'POST':
        url = request.form['url']
        result = check_url(url)
    return render_template('suslink.html', result=result)

@app.route('/link_awareness')
def link_awareness():
    return render_template('link_awareness.html')

@app.route('/privacy_awareness')
def privacy_awareness():
    return render_template('privacy_awareness.html')

@app.route('/quiz_start')
def quiz_start():
    return render_template('quiz_start.html')

def encode_message(image, message):
    message += "|||END|||"
    binary = ''.join([format(ord(c), '08b') for c in message])
    img = image.convert("RGB")
    pixels = img.load()

    width, height = img.size
    data_index = 0

    for y in range(height):
        for x in range(width):
            if data_index >= len(binary):
                break
            r, g, b = pixels[x, y]

            r = (r & ~1) | int(binary[data_index])
            data_index += 1
            if data_index < len(binary):
                g = (g & ~1) | int(binary[data_index])
                data_index += 1
            if data_index < len(binary):
                b = (b & ~1) | int(binary[data_index])
                data_index += 1

            pixels[x, y] = (r, g, b)

        if data_index >= len(binary):
            break

    return img

@app.route('/steganography', methods=['GET', 'POST'])
def steganography():
    if request.method == 'POST' and 'image' in request.files and 'message' in request.form:
        image = Image.open(request.files['image'])
        message = request.form['message']
        encoded_image = encode_message(image, message)

        img_io = io.BytesIO()
        encoded_image.save(img_io, 'PNG')
        img_io.seek(0)

        return send_file(img_io, mimetype='image/png', as_attachment=True, download_name='stego_image.png')

    return render_template('steganography.html')

# Steganography message extraction logic
def extract_message(img):
    img = img.convert("RGB")
    width, height = img.size

    binary_char = ""
    message = ""

    for y in range(height):
        for x in range(width):
            r, g, b = img.getpixel((x, y))

            for color in (r, g, b):
                binary_char += str(color & 1)

                if len(binary_char) == 8:
                    char = chr(int(binary_char, 2))
                    message += char
                    binary_char = ""

                    if message.endswith("|||END|||"):
                        return message[:-9]  # remove the end marker

    return message

# Route for decoding page
@app.route('/decode_steganography', methods=['GET', 'POST'])
def decode_steganography():
    if request.method == 'POST':
        if 'image' not in request.files:
            return render_template('decode_steganography.html', error="No file uploaded.")
        image = request.files['image']
        if image.filename == '':
            return render_template('decode_steganography.html', error="No selected file.")

        try:
            img = Image.open(image)
            message = extract_message(img)
            if not message:
                raise ValueError("No hidden message found or incorrect format.")
            return render_template('decode_steganography.html', message=message)
        except Exception as e:
            return render_template('decode_steganography.html', error=str(e))

    return render_template('decode_steganography.html')

if __name__ == '__main__':
    app.run(debug=True)
