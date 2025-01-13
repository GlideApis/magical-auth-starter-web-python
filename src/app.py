import os
import uuid
from flask import Flask, request, jsonify, send_from_directory, redirect
from glide_sdk import GlideClient
import asyncio
from functools import wraps

# Helper function to run async code in sync Flask routes
def async_route(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))
    return wrapped

app = Flask(__name__, 
    static_folder=os.path.join(os.path.dirname(__file__), 'static'),
    static_url_path=''
)

# Global variables to store session data
state_cache = {}
current_session = None

# Initialize Glide client
glide_client = GlideClient()

# Configuration
PORT = int(os.getenv('PORT', 8080))

@app.route('/')
def home():
    """Serve the main HTML page"""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/start-verification', methods=['POST'])
@async_route
async def start_verification():
    """Start the magic auth verification process"""
    try:
        phone_number = request.json.get('phoneNumber')
        print('Start Auth')
        
        session_id = str(uuid.uuid4())
        state_cache[session_id] = {
            'phoneNumber': phone_number,
            'status': 'pending'
        }
        
        auth_res = await glide_client.magic_auth.start_auth(
            phone_number=phone_number,
            state=session_id,
            redirect_url=os.getenv('MAGIC_REDIRECT_URI', f'http://localhost:{PORT}/'),
            fallback_channel='NO_FALLBACK'
        )
        
        # Convert the response object to a dictionary with correct fields
        response_dict = {
            'type': auth_res.type,
            'authUrl': auth_res.authUrl,
            'flatAuthUrl': auth_res.flatAuthUrl,
            'operatorId': auth_res.operatorId,
            'state': session_id
        }
        
        return jsonify(response_dict)
    except Exception as error:
        print(f'Error: {error}')
        return jsonify({'error': str(error)}), 400

@app.route('/api/check-verification', methods=['POST'])
@async_route
async def check_verification():
    """Verify the magic auth token"""
    try:
        data = request.json
        phone_number = data.get('phoneNumber')
        token = data.get('token')
        print('Check Auth')
        
        check_res = await glide_client.magic_auth.verify_auth(
            phone_number=phone_number,
            token=token
        )
        
        # Update session status if verification successful
        for session_id, session in state_cache.items():
            if session['phoneNumber'] == phone_number:
                session['status'] = 'verified' if check_res.verified else 'failed'
                break
        
        # Convert the response object to a dictionary with correct field
        response_dict = {
            'verified': check_res.verified
        }
        
        return jsonify(response_dict)
    except Exception as error:
        print(f'Error: {error}')
        return jsonify({'error': str(error)}), 400

@app.route('/api/get-session', methods=['POST'])
def get_session():
    """Retrieve session information"""
    try:
        state = request.json.get('state')
        print('Get Session')
        
        if state not in state_cache:
            return jsonify({'error': 'Session not found'}), 404
            
        session_data = state_cache[state]
        return jsonify({
            'phoneNumber': session_data['phoneNumber'],
            'status': session_data['status']
        })
    except Exception as error:
        print(f'Error: {error}')
        return jsonify({'error': str(error)}), 400

@app.route('/callback')
def callback():
    """Handle the callback from magic auth verification"""
    try:
        state = request.args.get('state')
        error = request.args.get('error')
        
        if state not in state_cache:
            return jsonify({'error': 'Invalid state parameter'}), 400
            
        if error:
            state_cache[state]['status'] = 'error'
            state_cache[state]['error'] = error
        else:
            state_cache[state]['status'] = 'callback_received'
            
        return send_from_directory(app.static_folder, 'index.html')
    except Exception as error:
        print(f'Error: {error}')
        return jsonify({'error': str(error)}), 400

if __name__ == '__main__':
    # Only for local development
    app.run(host='0.0.0.0', port=PORT, debug=True) 