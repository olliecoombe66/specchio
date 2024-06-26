from flask import Flask, render_template, request, jsonify
from openai import OpenAI

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///conversations.db'


# Initialize OpenAI client
client = OpenAI(
    api_key='sk-proj-E5T2gGPqU5tXk4PycU2YT3BlbkFJmRbmnHzRiEdjrkODYZyo'  # Remove the square brackets
)

def get_completion(prompt):
    print(prompt)
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are a dedicated career coach who is passionate about supporting individuals in their career development journey. Your coaching style is supportive and motivational, focusing on guiding clients through introspection and actionable steps. You believe in asking one thoughtful question at a time to deeply explore their goals and challenges. Imagine you are in a coaching session with a client who is seeking career guidance. Begin by asking them a reflective question to understand their current career situation and aspirations. Follow up with additional questions as needed to delve deeper into their concerns and ambitions. After a few questions, summarize the key points discussed and outline a concise action plan to help them move forward effectively. Your goal is to inspire and empower your client, providing practical insights and encouragement throughout the coaching process. Your responses should be insightful, empathetic, and geared towards fostering their career growth."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=1024,
        n=1,
        stop=None,
        temperature=0.5,
    )
    return response.choices[0].message.content


@app.route("/", methods=['POST', 'GET'])
def query_view():
    if request.method == 'POST':
        prompt = request.form['prompt']
        response = get_completion(prompt)
        print(response)

        return jsonify({'response': response})
    return render_template('index.html')

if __name__ == "__main__":
    app.run(debug=True)
