from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from dotenv import load_dotenv
import os
from openai import OpenAI
import markdown2
import uuid
from flask_mail import Mail, Message
from datetime import datetime as dt, timedelta
import json
import logging



#get environment variables
load_dotenv()
SECRET_KEY = os.getenv('SECRET_KEY')
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
MAIL_SERVER = os.getenv('MAIL_SERVER')
MAIL_PORT = os.getenv('MAIL_PORT')
MAIL_USE_TLS = os.getenv('MAIL_USE_TLS')
MAIL_USERNAME = os.getenv('MAIL_USERNAME')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')


# Initialize OpenAI client
client = OpenAI(
    api_key=OPENAI_API_KEY) # Remove the square brackets

#Set up databases
app = Flask(__name__, static_url_path='/static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///conversations.db'
app.secret_key = SECRET_KEY


app.config['MAIL_SERVER'] = MAIL_SERVER
app.config['MAIL_PORT'] = MAIL_PORT
app.config['MAIL_USE_TLS'] = MAIL_USE_TLS
app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD

mail = Mail(app)

#generate_session_id
def generate_session_id():
    return str(uuid.uuid4())

def save_message(user_id, role, session_id, content):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO conversations (user_id, role, session_id, content, message_count)
        VALUES (?, ?, ?, ?,
            (SELECT COALESCE(MAX(message_count), 0) + 1
             FROM conversations
             WHERE user_id = ? AND session_id = ? AND role = 'user'))
    ''', (user_id, role, session_id, content, user_id, session_id))
    conn.commit()
    conn.close()

# Database setup
def init_sqlite_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT UNIQUE NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            session_id TEXT,
            role TEXT,
            content TEXT,
            message_count INTEGER DEFAULT 0,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES user
            )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS actions (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            conversation_id TEXT,
            title TEXT NOT NULL,
            details TEXT,
            due_date DATE,
            status TEXT DEFAULT 'pending',
            objective TEXT
            objective_id TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            summary TEXT,
            session_id TEXT,
            date_created DATETIME
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            user_id TEXT,
            token TEXT,
            expiration_time DATETIME
        )
    ''')
    conn.commit()
    conn.close()

init_sqlite_db()

#create sessions (only if not already there)
def create_session(user_id, session_id, date_created):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # First, check if a session already exists for this user
    cursor.execute('SELECT session_id FROM sessions WHERE user_id = ?', (user_id,))
    existing_session = cursor.fetchone()

    if not existing_session:
        # If no session exists, create a new one
        cursor.execute('INSERT INTO sessions (user_id, session_id, date_created) VALUES (?, ?, ?)', (user_id, session_id, date_created))
        conn.commit()

    conn.close()


def update_session_summary(session_id, user_id, summary, date_time):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    try:
        # Check if the session exists
        cursor.execute('SELECT id FROM sessions WHERE session_id = ?', (session_id,))
        session = cursor.fetchone()

        if session:
            # If session exists, update the summary
            cursor.execute('UPDATE sessions SET summary = ? WHERE session_id = ?', (summary, session_id))
        else:
            # If session doesn't exist, insert new row (this shouldn't happen if sessions are created properly)
            cursor.execute('INSERT INTO sessions (session_id, user_id, summary, date_created) VALUES (?, ?, ?, ?)', (session_id, user_id, summary, date_time))

        conn.commit()
        print(f"Summary updated for session {session_id}")
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    finally:
        conn.close()

def generate_summary(conversation_history, max_length=50):
    # Combine all messages into one string
    full_conversation = " ".join([msg['content'] for msg in conversation_history])

    # Take the first `max_length` characters
    summary = full_conversation[:max_length]

    # Add ellipsis if the summary was truncated
    if len(full_conversation) > max_length:
        summary += "..."

    return summary

def get_session_ids(user_id):
    try:
        with sqlite3.connect('database.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT session_id, summary FROM sessions WHERE user_id = ? ORDER BY date_created DESC', (user_id,))
            sessions = cursor.fetchall()
        return [(session[0], session[1]) for session in sessions]
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        return []

def get_user_name(user_id):
    # Establish a connection to the SQLite database
    conn = sqlite3.connect('database.db')

    # Create a cursor object
    cursor = conn.cursor()

    # Execute the SELECT query
    cursor.execute('SELECT name FROM users WHERE id = ?', (user_id,))

    # Fetch the result
    user = cursor.fetchone()

    # Close the connection
    conn.close()

    # Check if a user was found and return the name, otherwise return None
    if user:

        return user[0]  # user[0] contains the 'name' field
    else:
        return None

def get_user_name_with_email(email):
    # Establish a connection to the SQLite database
    conn = sqlite3.connect('database.db')

    # Create a cursor object
    cursor = conn.cursor()

    # Execute the SELECT query
    cursor.execute('SELECT username FROM users WHERE username = ?', (email,))

    # Fetch the result
    user = cursor.fetchone()

    # Close the connection
    conn.close()

    # Check if a user was found and return the name, otherwise return None
    if user:
        return user[0]  # user[0] contains the 'name' field
    else:
        return None


def load_conversation_history(user_id, session_id, limit=10):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    if limit is None:
        # If no limit is specified, fetch all messages
        cursor.execute('''
            SELECT role, content FROM conversations
            WHERE user_id = ? AND session_id = ?
            ORDER BY timestamp ASC
        ''', (user_id, session_id))
    else:
        # If a limit is specified, fetch the most recent messages
        cursor.execute('''
            SELECT role, content FROM conversations
            WHERE user_id = ? AND session_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (user_id, session_id, limit))

    messages = cursor.fetchall()
    conn.close()

    # Reverse the order to get chronological order
    messages.reverse()

    return [{"role": role, "content": markdown2.markdown(content)} for role, content in messages]


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

#Create a fuction to generate a summary using ChatGPT
def generate_chat_summary(conversation_history):
    messages = [
        {"role": "system", "content": "You are a summarization assistant. Provide a brief summary of the conversation. Limit to less than 5 words."}
    ]
    messages.extend(conversation_history)

    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=messages,
        max_tokens=100,
        n=1,
        stop=None,
        temperature=0.5,
    )
    return response.choices[0].message.content

# Create actions
def create_user_action(user_id, conversation_id, title, details, due_date, objective, objective_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO actions (user_id, conversation_id, title, details, due_date, objective, objective_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (user_id, conversation_id, title, details, due_date))
    action_id = cursor.lastrowid

    conn.commit()
    conn.close()
    return action_id

# Get actions
def get_user_actions(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT a.id, a.title, a.details, a.due_date, a.status, a.objective, a.objective_id
        FROM actions a
        WHERE a.user_id = ?
        ORDER BY a.due_date ASC
    ''', (user_id,))
    actions = cursor.fetchall()
    conn.close()

    # Convert to list of dictionaries for easier handling in JavaScript
    return [
        {
            'id': action[0],
            'title': action[1],
            'details': action[2],
            'due_date': action[3],
            'status': action[4],
            'objective': action[5],
            'objective_id': action[6]

        }
        for action in actions
    ]

def get_user_actions_by_objective(user_id, objective):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT a.id, a.title, a.details, a.due_date, a.status, a.objective, a.objective_id
        FROM actions a
        WHERE a.user_id = ? AND a.objective_id = ?
        ORDER BY a.due_date ASC
    ''', (user_id, objective))
    actions = cursor.fetchall()
    conn.close()

    # Convert to list of dictionaries for easier handling in JavaScript
    return [
        {
            'id': action[0],
            'title': action[1],
            'details': action[2],
            'due_date': action[3],
            'status': action[4],
            'objective': action[5],
            'objective_id': action[6]

        }
        for action in actions
    ]

# Update actions
def update_action(action_id, title, details, due_date, status):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE actions
        SET title = ?, details = ?, due_date = ?, status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (title, details, due_date, status, action_id))

    conn.commit()
    conn.close()



def save_reset_token(user_id, token):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO password_reset_tokens (user_id, token, expiration_time) VALUES (?, ?, ?)',
                   (user_id, token, dt.now() + timedelta(hours=1)))
    conn.commit()
    conn.close()

def get_user_by_reset_token(token):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM password_reset_tokens WHERE token = ? AND expiration_time >= ?', (token, dt.now()))
    token_data = cursor.fetchone()
    print(f"get_user_reset_token {token_data}")
    if token_data:
        user_id = token_data[0]
        cursor.execute('SELECT * FROM users WHERE username = ?', (user_id,))
        user = cursor.fetchone()
    else:
        user = None

    conn.close()
    return user

def update_user_password(user_id, hashed_password):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, user_id))
    conn.commit()
    conn.close()

def clear_reset_token(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM password_reset_tokens WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()


@app.route('/', methods=['POST', 'GET'])
def query_view():
    return render_template('landing-page.html')


@app.route('/chat', methods=['POST', 'GET'])
@app.route('/chat/<session_id>', methods=['POST', 'GET'])
def query_view2(session_id=None):
    if 'conversation_history' not in session:
        session['conversation_history'] = []
    # Fetch user's name from the database using user_id stored in session
    user_id = session.get('user_id')
    user_name = get_user_name(user_id) if user_id else None

    # Determine the session_id to use
    if session_id is None:
        session_id = session.get('session_id')
    else:
        session['session_id'] = session_id  # Update session_id in session

    session_ids = get_session_ids(user_id)



    if request.method == 'POST':
        prompt = request.form['prompt']

        # Save user message
        save_message(user_id, 'user', session_id, prompt)

        # Get the response from ChatGPT
        response = get_completion(prompt, session['conversation_history'])

        # Save assistant message
        save_message(user_id, 'assistant', session_id, response)

        # Update the conversation history
        session['conversation_history'].append({"role": "user", "content": prompt})
        session['conversation_history'].append({"role": "assistant", "content": response})

        # Limit the conversation history to the last 100 messages (adjust as needed)
        session['conversation_history'] = session['conversation_history'][-100:]
        html_response = markdown2.markdown(response)
        history = load_conversation_history(session['user_id'], session_id)
        create_session(user_id, session['session_id'], dt.now())

        #update summary
        conversation_history = load_conversation_history(session['user_id'], session_id)

        # Check if it's time to generate a summary
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT COUNT(*) FROM conversations
            WHERE user_id = ? AND session_id = ? AND role = 'user'
        ''', (user_id, session_id))
        message_count = cursor.fetchone()[0]
        conn.close()




        if message_count == 2:  # Every 3 user messages
            summary = generate_chat_summary(session['conversation_history'])
            update_session_summary(session_id, session['user_id'], summary, dt.now())

        session.modified = True
        return jsonify({'response': html_response})

    return render_template('index.html', user_name=user_name, session_ids=session_ids, session_id=session_id)


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
            # Create a new session entry in the database
            session['session_id'] = generate_session_id()
            session['user_id'] = user[0]


            session['username'] = username
            session['conversation_history'] = load_conversation_history(user[0], session['session_id'])


            return redirect(url_for('query_view2'))
        else:
            flash('Invalid username or password')

    return render_template('login.html')





def send_password_reset_email(email, token):
    reset_link = url_for('reset_password', token=token, _external=True)
    msg = Message('Password Reset Request', sender='your-email@example.com', recipients=[email])
    msg.body = f'Hello,\n\nTo reset your password, click on the following link:\n{reset_link}\n\nIf you did not request this, please ignore this email.\n'
    mail.send(msg)

#Signup flow
@app.route('/signup2', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        name = request.form['name']

        try:
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password, name) VALUES (?, ?, ?)', (username, password, name))
            conn.commit()
            conn.close()
            flash('Signup successful! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already taken')

    return render_template('signup.html')

#Landing page
@app.route('/home', methods=['GET'])
def landingPage():
    return render_template('landing-page.html')

#Get conversation history
@app.route('/get_conversation_history')
def get_conversation_history():
    if 'user_id' not in session:
        return jsonify({'history': []})
    history = load_conversation_history(session['user_id'], session['session_id'])
    return jsonify({'history': history})

#Logout flow
@app.route('/logout')
def logout():
    # Clear the session data
    session.clear()
    print("logout")
    flash('You have been logged out successfully.')
    return redirect(url_for('query_view'))

#Reset password flow
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        user = get_user_name_with_email(email)

        if user:
            token = str(uuid.uuid4())
            save_reset_token(email, token)  # Save token in database
            send_password_reset_email(email, token)  # Send email with reset link
            flash('Password reset email sent. Please check your email.')
            return redirect(url_for('login'))
        else:
            flash('Email address not found.')

    return render_template('reset_password.html')

#Creates token for reset password
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    print(f"Token: {token}")
    user = get_user_by_reset_token(token)

    if not user:
        flash('Invalid or expired reset link.')
        return redirect(url_for('login'))

    if isinstance(user, tuple):
        user_id, email = user[0], user[1]
    else:
        # Assuming user is a dictionary
        user_id, email = user.get('id'), user.get('email')

    print(f"User ID: {user_id}, Email: {email}")

    if request.method == 'POST':
        try:
            password = request.form['password']
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            update_user_password(user_id, hashed_password)
            clear_reset_token(user_id)  # Use user_id instead of user['id']
            flash('Your password has been reset successfully. Please log in.')
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Error in password reset: {str(e)}")
            flash('An error occurred while resetting your password. Please try again.')

    return render_template('reset_password_form.html', token=token)

#Creates new sessions
@app.route('/new_session', methods=['POST'])
def new_session():
    session['session_id'] = generate_session_id()
    new_session_id = session['session_id']
    return jsonify({
        'session_id': new_session_id,
        'redirect_url': url_for('query_view2', session_id=new_session_id)
    })

#Actions page
@app.route('/actions')
@app.route('/actions/<objective>', methods=['POST', 'GET'])
def actions(objective=None):
    print(objective)
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    session_ids = get_session_ids(user_id)
    user_actions = get_user_actions(user_id)
    print(objective)
    print(user_id)
    actions = get_user_actions_by_objective(user_id, objective)

    print(actions)

    unique_objectives = {(item['objective'], item['objective_id']) for item in user_actions}
    print(unique_objectives)

    user_name = get_user_name(user_id)

    return render_template('actions.html',
                           actions=actions,
                           user_name=user_name,
                           session_id=session.get('session_id'),
                           session_ids=session_ids,
                           objective=objective,
                           unique_objectives=unique_objectives,
                           )



@app.route('/extract_actions', methods=['POST'])
def extract_actions():
    user_id = session.get('user_id')
    session_id = session.get('session_id')

    # Fetch the entire conversation
    conversation = load_conversation_history(user_id, session_id, limit=None)

    # Prepare the prompt for OpenAI
    prompt = (
        "Extract actionable items from the following conversation. "
        "Respond with a JSON object containing an 'actions' key, which is an array of action objects. "
        "Each action object should have 'objective', 'objective_id, title', 'details', and 'due_date' fields. Objective should be the same across all generated actions."
        "objective_id should be set to same value as 'objective' but converted to snake case."
        "Make sure in the 'title' that the action is Specific, Measurable, Actionable, Realistic and Time bound/n/n"

    )
    prompt += "\n".join([f"{msg['role']}: {msg['content']}" for msg in conversation])

    # Prepare the messages for the OpenAI API call
    messages = [
        {"role": "system", "content": "You are an AI assistant that extracts actionable items from conversations and responds in JSON format."},
        {"role": "user", "content": prompt}
    ]

    # Call OpenAI API
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        response_format={ "type": "json_object" },
        messages=messages,
        max_tokens=1000,
        n=1,
        stop=None,
        temperature=0.5,
    )

    # Log the raw response content
    logging.info(f"OpenAI raw response: {response.choices[0].message.content}")


    # Parse the response
    try:
        response_data = json.loads(response.choices[0].message.content)
        actions = response_data.get('actions', [])
        logging.info(f"Parsed actions: {actions}")
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse OpenAI response: {e}")
        actions = []

    # If no actions were extracted or if parsing failed, add a dummy action
    if not actions:
        logging.warning("No actions found or parsing failed. Adding dummy action.")
        actions = [{"title": "Dummy Action", "details": "No actions were identified in the conversation. This is a placeholder action.", "due_date": ""}]

    # Prepare debug information
    debug_info = {
        "request": {
            "messages": messages,
            "max_tokens": 1000,
            "temperature": 0.5
        },
        "response": response.dict()  # Convert the response object to a dictionary
    }

    return jsonify({
        "actions": actions,
        "request": debug_info["request"],
        "response": debug_info["response"]
    })

# Add this route to save actions
@app.route('/save_actions', methods=['POST'])
def save_actions_route():
    user_id = session.get('user_id')
    actions = request.json.get('actions')
    save_actions(user_id, actions)
    return jsonify({"success": True})

def save_actions(user_id, actions):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    for action in actions:
        cursor.execute('''
            INSERT INTO actions (user_id, conversation_id, title, details, due_date, objective, objective_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, session.get('session_id'), action['title'], action['details'], action['due_date'], action['objective'], action['objective_id']))
    conn.commit()
    conn.close()

# Fetch actions for display
@app.route('/get_actions')
def get_actions():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'actions': []})

    actions = get_user_actions(user_id)
    return jsonify({'actions': actions})

@app.route('/complete_action', methods=['POST'])
def complete_action():
    print("Action triggered")
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'error': 'User not logged in'}), 401

    action_id = request.json.get('action_id')
    if not action_id:
        return jsonify({'success': False, 'error': 'No action_id provided'}), 400

    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE actions
            SET status = 'completed', updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND user_id = ?
        ''', (action_id, user_id))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Action marked as completed'})
    except sqlite3.Error as e:
        return jsonify({'success': False, 'error': str(e)}), 500



if __name__ == "__main__":
    app.run(debug=True)
