from flask import Flask, request, jsonify
from matplotlib import text
from features.feature_engineering import predict_from_webcode, predict_from_url

app = Flask(__name__)


@app.route("/predict/url", methods=["POST"])
def predict_url():
    data = request.json
    url = data["text"]
    prediction = predict_from_url(url)
    print(f"Predicted result for URL {url}: {prediction}")
    return jsonify(prediction)


@app.route("/predict/webcode", methods=["POST"])
def predict_webcode():
    data = request.json
    text, url = data["text"], data["url"]
    print(f"Received URL for prediction: {url}")

    prediction = predict_from_webcode(text, url)

    return jsonify(prediction)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
