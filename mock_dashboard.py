from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/agent', methods=['POST'])
def receive_agent_data():
    data = request.json
    print("Received data from agent:")
    print(data)
    return jsonify({"status": "success"}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
