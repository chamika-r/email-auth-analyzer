"""
Flask Web Application
Web interface for the email authentication analyzer.
"""

import os
import json
import tempfile
from flask import Flask, render_template, request, jsonify
from analyzer import analyze

app = Flask(
    __name__,
    template_folder='../templates'
)

app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max upload


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze_email():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not file.filename.endswith('.eml'):
        return jsonify({'error': 'Only .eml files are supported'}), 400

    # Save to temp file, analyze, delete
    with tempfile.NamedTemporaryFile(suffix='.eml', delete=False) as tmp:
        file.save(tmp.name)
        tmp_path = tmp.name

    try:
        result = analyze(tmp_path)
        result['file'] = file.filename
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        os.unlink(tmp_path)


@app.route('/health')
def health():
    return jsonify({'status': 'healthy'})


if __name__ == '__main__':
    app.run(debug=True, port=5000)