import os
import base64
import json
import re
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request
import requests
from datetime import datetime
from phishing_checker import check_phishing

# If modifying, delete the token.json file to reauthorize
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def authenticate_gmail():
    """Authenticate with Gmail API"""
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=8888)
        
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    
    return build('gmail', 'v1', credentials=creds)

def setup_watch(service):
    """Set up Gmail watch for Pub/Sub notifications"""
    try:
        service.users().watch(userId='me', body={
            'labelIds': ['INBOX'],
            'topicName': 'Your TOPIC name'
        }).execute()
        print("Watch request set successfully.")
    except HttpError as error:
        print(f"An error occurred: {error}")
    

import base64
from googleapiclient.discovery import build

def get_email_content_from_history(service, history_id):
    """Fetch email content using Gmail API with historyId"""
    try:
        # Retrieve history data
        results = service.users().history().list(userId='me', startHistoryId=history_id).execute()

        history = results.get('history', [])
        if history:
            for event in history:
                for message in event.get('messagesAdded', []):
                    message_id = message['message']['id']
                    print(f"Found message ID: {message_id}")
                    email_content = get_email_content(service, message_id)
                    if email_content:
                        print(f"Email Content: {email_content}")
                    else:
                        print("Failed to fetch email content")
        else:
            print("No history found.")
    except Exception as e:
        print(f"Error fetching email: {e}")

def get_email_content(service, message_id):
    """Get email content using messageId"""
    try:
        message = service.users().messages().get(userId='me', id=message_id).execute()
        payload = message['payload']
        body = payload.get('body', {}).get('data')
        
        if body:
            email_content = base64.urlsafe_b64decode(body).decode('utf-8')
            return email_content
        else:
            return None
    except Exception as e:
        print(f"Error retrieving message content: {e}")
        return None







