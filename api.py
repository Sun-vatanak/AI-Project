from flask import Flask, render_template
import requests

app = Flask(__name__)

def fetch_aqi_data():
    api_url = "http://api.airvisual.com/v2/nearest_city?key=02513edd-d34b-4344-81b6-dab04ca2ca62"
    try:
        response = requests.get(api_url)
        response.raise_for_status()  # Raise an error for bad status codes
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching AQI data: {e}")
        return None

@app.route('/')
def index():
    return render_template('test.html')

@app.route('/get-aqi')
def get_aqi():
    aqi_data = fetch_aqi_data()
    return aqi_data if aqi_data else {"error": "Unable to fetch AQI data"}

if __name__ == '__main__':
    app.run(debug=True)