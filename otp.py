import os
from dotenv import load_dotenv
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from pymongo import MongoClient, errors
import bcrypt
import requests
import google.generativeai as genai
import datetime
import random
import time
import threading
import time
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
from pprint import pprint

# Load environment variables
load_dotenv()

# Validate environment variables
required_env_vars = ['SENDGRID_API_KEY', 'SENDER_EMAIL', 'MONGO_URI', 'GEMINI_API_KEY']
for var in required_env_vars:
    if not os.getenv(var):
        raise EnvironmentError(f"Missing required environment variable: {var}")

SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')
SENDER_EMAIL = os.getenv('SENDER_EMAIL')
MONGO_URI = os.getenv("MONGO_URI")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# Create Flask app
app = Flask(__name__)
CORS(app)

app.secret_key = "a_very_long_random_string_1234567890!@#$%"
# Connect to MongoDB with error handling
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.server_info()  # Force connection on startup
    db = client['login_db']
    users_collection = db['users']
    scores_collection = db['scores']
    quizzes_collection = db['quizzes']
    print("✅ MongoDB connected successfully.")
except errors.ServerSelectionTimeoutError as err:
    print("❌ MongoDB connection failed:", err)
    raise SystemExit("Exiting due to MongoDB connection failure.")

# Users to insert
preexisting_users = [
    {
        'email': 'nikhil@gvpce.ac.in',
        'password': bcrypt.hashpw('teacher123'.encode('utf-8'), bcrypt.gensalt()),
        'role': 'teacher'
    }
]

for i in range(323103383001, 323103383071):
    preexisting_users.append({
        'email': f'{i}@gvpce.ac.in',
        'password': bcrypt.hashpw('student123'.encode('utf-8'), bcrypt.gensalt()),
        'role': 'student'
    })

# Insert users (ignore if already exists)
for user in preexisting_users:
    if not users_collection.find_one({'email': user['email']}):
        users_collection.insert_one(user)
        print(f"✅ Inserted: {user['email']} ({user['role']})")
    else:
        print(f"⚠️ Already exists: {user['email']}")

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Missing email or password'}), 400

    user = users_collection.find_one({'email': email})
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'error': 'Incorrect password'}), 401

@app.route('/api/quiz/<quiz_id>/grade', methods=['POST'])
def grade_quiz(quiz_id):
    try:
        data = request.json
        student_answers = data.get('answers', [])  # [{questionIndex: 0, answer: "A"}, ...]

        quiz = quizzes_collection.find_one({'_id': ObjectId(quiz_id)})
        if not quiz:
            return jsonify({'error': 'Quiz not found'}), 404

        questions = quiz.get('questions', [])
        score = 0
        results = []

        for ans in student_answers:
            q_idx = ans.get('questionIndex')
            student_answer = ans.get('answer')

            if q_idx is None or q_idx >= len(questions):
                continue

            correct_answer = questions[q_idx].get('answer')
            is_correct = (student_answer == correct_answer)

            results.append({
                'questionIndex': q_idx,
                'studentAnswer': student_answer,
                'isCorrect': is_correct,
                # Do NOT send correctAnswer if you want to hide it here
            })

            if is_correct:
                score += 1

        return jsonify({
            'score': score,
            'total': len(questions),
            'results': results
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/submitScore', methods=['POST'])
def submit_score():
    try:
        data = request.get_json()
        quiz_id = data.get('quizId')
        student_roll_no = data.get('studentRollNo')
        score = data.get('score')
        total = data.get('total')

        if not all([quiz_id, student_roll_no, score is not None, total]):
            return jsonify({'error': 'Missing data'}), 400

        # Validate quiz ID
        if not quizzes_collection.find_one({'_id': ObjectId(quiz_id)}):
            return jsonify({'error': 'Invalid quizId'}), 404

        # Prevent duplicate submissions
        existing = scores_collection.find_one({
            'quizId': ObjectId(quiz_id),
            'studentRollNo': student_roll_no
        })
        if existing:
            return jsonify({'message': 'Score already submitted'}), 409

        # Insert new score
        scores_collection.insert_one({
            'quizId': ObjectId(quiz_id),
            'studentRollNo': student_roll_no.strip(),
            'score': int(score),
            'total': int(total),
            'submittedAt': datetime.datetime.utcnow()
        })

        return jsonify({'message': 'Score submitted successfully'}), 200

    except Exception as e:
        print(f"Error in /api/submitScore: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400

    if users_collection.find_one({'email': email}):
        return jsonify({'error': 'User already exists'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    users_collection.insert_one({
        'email': email,
        'password': hashed_password
    })

    return jsonify({'message': 'User registered successfully'}), 201

# In-memory OTP store
otp_store = {}
OTP_EXPIRY_SECONDS = 300  # 5 minutes

# Start cleanup thread
def cleanup_otps():
    while True:
        now = time.time()
        expired = [email for email, (_, expiry) in otp_store.items() if expiry < now]
        for email in expired:
            del otp_store[email]
        time.sleep(60)

cleanup_thread = threading.Thread(target=cleanup_otps, daemon=True)
cleanup_thread.start()

# Brevo Configuration
BREVO_API_KEY = os.getenv('BREVO_API_KEY')
SENDER_EMAIL = "quizdmn@gmail.com"
SENDER_NAME = "Quiz Admin"

# Configure API key
configuration = sib_api_v3_sdk.Configuration()
configuration.api_key['api-key'] = BREVO_API_KEY
api_client = sib_api_v3_sdk.ApiClient(configuration)
smtp_api = sib_api_v3_sdk.TransactionalEmailsApi(api_client)

@app.route('/send-otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'success': False, 'message': 'Missing email'}), 400

    otp = str(random.randint(100000, 999999))
    expiry = time.time() + OTP_EXPIRY_SECONDS
    otp_store[email] = (otp, expiry)
    print(f"[send-otp] OTP for {email}: {otp}")
    print(otp)

    # Prepare Brevo email
    email_data = sib_api_v3_sdk.SendSmtpEmail(
        to=[{"email": email}],
        sender={"name": SENDER_NAME, "email": SENDER_EMAIL},
        subject="Your OTP Code",
        html_content=f"<strong>Your OTP code is: {otp}</strong>"
    )

    try:
        response = smtp_api.send_transac_email(email_data)
        print(f"Brevo response message ID: {response.message_id}")
        return jsonify({'success': True, 'message': 'OTP sent successfully'}), 200
    except ApiException as e:
        print(f"Brevo error: {e}")
        return jsonify({'success': False, 'message': 'Failed to send OTP'}), 500

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    entered_otp = data.get('otp')
    if not email or not entered_otp:
        return jsonify({'success': False, 'message': 'Missing email or OTP'}), 400

    stored = otp_store.get(email)
    if not stored:
        return jsonify({'success': False, 'message': 'No OTP found or expired'}), 401

    otp, expiry = stored
    if time.time() > expiry:
        del otp_store[email]
        return jsonify({'success': False, 'message': 'OTP expired'}), 401

    if entered_otp == otp:
        del otp_store[email]  # remove OTP after success
        return jsonify({'success': True, 'message': 'OTP verified successfully'}), 200
    else:
        return jsonify({'success': False, 'message': 'Invalid OTP'}), 401


@app.route('/generate-quiz', methods=['POST'])
def generate_quiz():
    try:
        data = request.get_json()
        topic = data.get('topic')
        difficulty = data.get('difficulty')
        num_questions = data.get('numQuestions')

        if not topic or not difficulty or not num_questions:
            return jsonify({'error': 'Missing required fields'}), 400

        prompt = (
            f"Generate {num_questions} multiple-choice questions on the topic '{topic}' "
            f"at a {difficulty} difficulty level. Each question should have 4 options "
            "labelled A, B, C, D and include the correct answer. "
            "Format the response as a JSON array like this: "
            "[{{\"question\": \"...\", \"options\": [\"...\", \"...\", \"...\", \"...\"], \"answer\": \"A,B,C,D and include the correct answer\"}}, ...]"
        )

        GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
        if not GEMINI_API_KEY:
            return jsonify({'error': 'GEMINI_API_KEY not set'}), 500

        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={GEMINI_API_KEY}"

        try:
            response = requests.post(
                url,
                json={"contents": [{"parts": [{"text": prompt}]}]},
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print("RequestException:", str(e))
            return jsonify({'error': 'RequestException', 'details': str(e)}), 500

        gemini_data = response.json()
        print("Gemini response:", gemini_data)

        text_response = gemini_data['candidates'][0]['content']['parts'][0]['text']

        import re
        json_match = re.search(r'(\[.*\])', text_response, re.DOTALL)
        if not json_match:
            print("No JSON array found in text_response:", text_response)
            return jsonify({'error': 'Could not find JSON formatted questions in the response', 'raw_text': text_response}), 500

        json_text = json_match.group(1)

        import json
        try:
            questions = json.loads(json_text)
        except Exception as e:
            print("JSON parsing error:", str(e))
            return jsonify({'error': f'Failed to parse JSON: {str(e)}', 'raw_json': json_text}), 500

        return jsonify({'questions': questions}), 200

    except Exception as e:
        print("Unhandled exception:", str(e))
        return jsonify({'error': f"Exception: {str(e)}"}), 500

@app.route('/api/quizzes', methods=['GET'])
def get_all_quizzes():
    try:
        quizzes = []
        for quiz in quizzes_collection.find({}):
            quiz['_id'] = str(quiz['_id'])
            quizzes.append(quiz)
        return jsonify(quizzes), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


from bson.objectid import ObjectId

@app.route('/api/quiz/<quiz_id>', methods=['GET'])
def get_quiz_by_id(quiz_id):
    try:
        quiz = quizzes_collection.find_one({'_id': ObjectId(quiz_id)})
        if not quiz:
            return jsonify({'error': 'Quiz not found'}), 404

        quiz['_id'] = str(quiz['_id'])  # Convert ObjectId to string for JSON

        # Do NOT remove the answers
        return jsonify(quiz), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    new_password = data.get('password')

    if not email:
        return jsonify({'success': False, 'message': 'Missing email'}), 400

    if not new_password:
        return jsonify({'success': False, 'message': 'Missing password'}), 400

    if len(new_password) < 6:
        return jsonify({'success': False, 'message': 'Password too short (minimum 6 characters)'}), 400

    # Hash the new password securely using bcrypt
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

    # Update the password in the database
    result = users_collection.update_one(
        {'email': email},
        {'$set': {'password': hashed_password}}
    )

    if result.modified_count == 1:
        return jsonify({'success': True, 'message': 'Password updated successfully'}), 200
    else:
        return jsonify({'success': False, 'message': 'Failed to update password or email not found'}), 500

    
@app.route('/api/quizzes', methods=['POST'])
def upload_quiz():
    data = request.json
    print("Received quiz upload:", data)  # <--- confirm data is received

    required_fields = ['createdBy', 'topic', 'difficulty', 'questions']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required quiz data'}), 400

    quiz = {
        'createdBy': data['createdBy'],
        'topic': data['topic'],
        'difficulty': data['difficulty'],
        'questions': data['questions'],
        'assignedTo': data.get('assignedTo', ''),
        'numQuestions': len(data['questions'])
    }

    try:
        quizzes_collection.insert_one(quiz)
        print("Quiz saved successfully.")
        return jsonify({'message': 'Quiz uploaded successfully'}), 201
    except Exception as e:
        print("DB error:", str(e))
        return jsonify({'error': 'Database error', 'details': str(e)}), 500


from bson import ObjectId

@app.route('/api/my-quizzes/<teacher_id>', methods=['GET'])
def get_my_quizzes(teacher_id):
    try:
        quizzes_cursor = quizzes_collection.find({'createdBy': teacher_id})  # include _id by default
        quizzes = []
        for quiz in quizzes_cursor:
            quiz['_id'] = str(quiz['_id'])  # convert ObjectId to string
            quizzes.append(quiz)
        return jsonify(quizzes), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


from bson.objectid import ObjectId

@app.route('/api/quiz/<quiz_id>', methods=['DELETE'])
def delete_quiz(quiz_id):
    try:
        quiz_obj_id = ObjectId(quiz_id)

        # Step 1: Delete quiz
        quiz_result = quizzes_collection.delete_one({'_id': quiz_obj_id})

        if quiz_result.deleted_count == 0:
            return jsonify({'error': 'Quiz not found'}), 404

        # Step 2: Delete associated scores
        scores_result = scores_collection.delete_many({'quizId': quiz_obj_id})

        return jsonify({
            'message': 'Quiz and associated scores deleted',
            'quiz_deleted': quiz_result.deleted_count,
            'scores_deleted': scores_result.deleted_count
        }), 200

    except Exception as e:
        return jsonify({
            'error': 'Error deleting quiz and scores',
            'details': str(e)
        }), 500

@app.route('/get-student-scores-by-quiz', methods=['POST'])
def get_student_scores_by_quiz():
    data = request.json
    teacher_email = data.get("teacherEmail")
    quiz_id = data.get("quizId")
    roll_prefix = data.get("studentRollNo", "").strip()

    if not teacher_email or not quiz_id:
        return jsonify({"error": "Missing data"}), 400

    # Validate teacher owns the quiz
    quiz = quizzes_collection.find_one({"_id": ObjectId(quiz_id), "createdBy": teacher_email})
    if not quiz:
        return jsonify({"error": "Quiz not found or not authorized"}), 404

    # Build query
    query = {"quizId": ObjectId(quiz_id)}
    if roll_prefix:
        query["studentRollNo"] = {"$regex": f"^{roll_prefix}"}

    scores = list(scores_collection.find(query))
    result = []

    for s in scores:
        result.append({
            "topic": quiz.get("topic", "Unknown"),
            "studentRollNo": s["studentRollNo"],
            "score": s["score"],
            "total": s["total"],
            "submittedAt": s["submittedAt"].isoformat()
        })

    return jsonify(result)

@app.route('/')
def index():
    return "✅ Flask Quiz API is running!"


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
