from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from dotenv import load_dotenv
import os
from openai import OpenAI
import markdown2

#get environment variables
load_dotenv()
SECRET_KEY = os.getenv('SECRET_KEY')
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')

# Initialize OpenAI client
client = OpenAI(
    api_key=OPENAI_API_KEY) # Remove the square brackets

#Set up databases
app = Flask(__name__, static_url_path='/static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///conversations.db'
app.secret_key = SECRET_KEY



# Database setup
def init_sqlite_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_sqlite_db()


# Modify the get_completion function
def get_completion(prompt, conversation_history):
    messages = [
        {"role": "system", "content": "You are a proactive and empathetic career coach, dedicated to passionately supporting individuals in their career development journey. Your coaching style is not only supportive and motivational but also focuses on providing actionable steps and practical advice. Your responses should be insightful, empathetic, and geared towards fostering their career growth. While you do believe in asking thoughtful questions to explore their goals and challenges, you balance this with solid, actionable advice. After a few questions, summarize the key points discussed and outline a concise action plan titled 'Your Action Plan' to help them move forward effectively."}
    ]

    # Add conversation history
    messages.extend(conversation_history)

    # Add the new user message
    messages.append({"role": "user", "content": prompt})

    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=messages,
        max_tokens=1024,
        n=1,
        stop=None,
        temperature=0.5,
    )
    return response.choices[0].message.content


@app.route('/', methods=['POST', 'GET'])
def query_view():
    return render_template('landing-page.html')


@app.route('/chat', methods=['POST', 'GET'])
def query_view2():
    if 'conversation_history' not in session:
        session['conversation_history'] = []

    if request.method == 'POST':
        prompt = request.form['prompt']

        # Get the response from ChatGPT
        response = get_completion(prompt, session['conversation_history'])

        # Update the conversation history
        session['conversation_history'].append({"role": "user", "content": prompt})
        session['conversation_history'].append({"role": "assistant", "content": response})

        # Limit the conversation history to the last 10 messages (adjust as needed)
        session['conversation_history'] = session['conversation_history'][-10:]
        html_response = markdown2.markdown(response)

        # Make sure to mark the session as modified
        session.modified = True
        return jsonify({'response': html_response})
        print(html_response)
    return render_template('index.html')

@app.route('/login2', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['username'] = username
            return redirect(url_for('query_view2'))
        else:
            flash('Invalid username or password')

    return render_template('login.html')

@app.route('/signup2', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')

        try:
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            conn.commit()
            conn.close()
            flash('Signup successful! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already taken')

    return render_template('signup.html')

@app.route('/home', methods=['GET'])
def landingPage():
    return render_template('landing-page.html')



if __name__ == "__main__":
    app.run(debug=True)
