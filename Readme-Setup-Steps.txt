#1. Clone the Repository
git clone https://github.com/1Sundaram/hexguard.git
cd hexguard

#2. Set up a virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
#source venv/bin/activate       # Linux/macOS

#3. Install Dependencies
pip install -r requirements.txt

#4. Run the App Locally
waitress-serve --host=127.0.0.1 --port=5500 app:app 
