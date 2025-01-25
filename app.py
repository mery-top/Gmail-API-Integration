from flask import Flask, request, jsonify, render_template
from transformers import BertTokenizer, BertForSequenceClassification
import torch
import tensorflow as tf
import numpy as np
import base64
import json
import pickle
from flask_socketio import SocketIO
from email_fetcher import authenticate_gmail, setup_watch, get_email_content_from_history

app = Flask(__name__)
socketio = SocketIO(app)

model = BertForSequenceClassification.from_pretrained('phishing-detector')
tokenizer = BertTokenizer.from_pretrained('phishing-detector')


device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model.to(device)

service = authenticate_gmail()
setup_watch(service)


model2 = tf.keras.models.load_model('phishing_url_model.h5')
with open('vectorizer.pkl', 'rb') as f:
    vectorizer = pickle.load(f)

def predict(text):
    inputs = tokenizer(text, return_tensors='pt', truncation=True, padding=True, max_length=512).to(device)

    
    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        predicted_class = torch.argmax(logits, dim=1).item()
        
    return predicted_class

@app.route('/')
def index():
    return  render_template('index.html') 

@app.route('/home')
def home():

    return render_template('home.html')

@app.route('/analysis')
def analysis():
    return render_template('analysis.html')

@app.route('/cyberai')
def cyberai():
    return render_template('cyberai.html')

@app.route('/predict', methods=['POST'])
def predict_route():
    try:
        print("Request JSON:", request.get_json())


        data = request.get_json()


        if data is None:
            raise ValueError("No JSON data provided")

        message = data.get('message')
        
        if not message:
            raise ValueError("Message is required")

        prediction = predict(message)
        
        return jsonify({'prediction': prediction})
    
    except Exception as e:

        return jsonify({'error': str(e)}), 400


@app.route('/detect', methods=['POST'])
def detect_phishing():
    if not model2 or not vectorizer:
        return jsonify({"error": "Model or vectorizer not loaded properly"}), 500

    try:
        # Parse incoming JSON request
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "Invalid input. Please provide a 'url' field."}), 400
        
        url = data['url']
        print(f"Received URL: {url}")

        # Define class labels before referencing them
        class_labels = ['benign', 'defacement', 'phishing', 'malware']
        
        # Transform the URL using the vectorizer
        url_features = vectorizer.transform([url]).toarray()
        print(f"Transformed features: {url_features.shape}")
        
        # Make a prediction
        prediction = model2.predict(url_features)
        print(f"Raw prediction output: {prediction}") 
        if prediction.ndim != 2 or prediction.shape[1] != len(class_labels):
            raise ValueError(f"Unexpected prediction shape: {prediction.shape}")
        
        class_idx = np.argmax(prediction)
        class_label = class_labels[class_idx]
        confidence = prediction[0][class_idx]
        
        # Return the result
        return jsonify({
            'url': url,
            'type': class_label,
            'confidence': float(confidence)
        })
    except Exception as e:
        # Handle unexpected errors
        return jsonify({"error": f"An error occurred during detection: {str(e)}"}), 500

@app.route('/pubsub/push', methods=['POST'])
def pubsub_push():
    """Endpoint to receive Pub/Sub messages."""
    envelope = request.get_json()
    print("Envelope received:", envelope)

    if not envelope or 'message' not in envelope:
        return "Invalid Pub/Sub message format", 400

    message = envelope['message']
    print("Message received:", message)

    # Decode the base64-encoded data
    try:
        decoded_data = base64.b64decode(message['data']).decode('utf-8')
        print("Decoded message data:", decoded_data)
    except Exception as e:
        print(f"Error decoding base64 data: {e}")
        return "Error decoding message data", 500

    # Try parsing as JSON, skip if not JSON
    try:
        notification_data = json.loads(decoded_data)
        print("Parsed JSON data:", notification_data)
        email_address = notification_data.get('emailAddress')
        history_id = notification_data.get('historyId')
        if history_id:
            print(f"Processing historyId: {history_id}")        
            service = authenticate_gmail()  
            get_email_content_from_history(service, history_id)
        else:
            print("No valid historyId found in message.")

        print(f"Email Address: {email_address}, History ID: {history_id}")

    except json.JSONDecodeError:
        print("Decoded data is not valid JSON. Skipping JSON processing.")
        pass

    return "Message processed", 200


if __name__ == "__main__":
    socketio.run(app, debug=True, port=5173)