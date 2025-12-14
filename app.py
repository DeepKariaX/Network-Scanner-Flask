import os
from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def index():
    return "Hello, Flask!"

# Add other routes and application logic here as needed for the Network Scanner

if __name__ == '__main__':
    # Determine debug mode from the FLASK_DEBUG environment variable.
    # It will be True if FLASK_DEBUG is set to '1', 'true', 'True', etc.
    # It will default to False if FLASK_DEBUG is not set or set to '0', 'false', etc.
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')

    # Run the Flask application with the determined debug mode
    # Ensure host and port are also configured appropriately for production
    app.run(debug=debug_mode, host='0.0.0.0', port=5000) # Adjust host/port as needed