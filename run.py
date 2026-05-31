from app import create_app

# Instantiate the Flask Monolith app context
app = create_app()

if __name__ == '__main__':
    # Start debug server
    print("[Threat Intel Portal] Booting server at http://127.0.0.1:5000...")
    app.run(debug=True, host='127.0.0.1', port=5000)
