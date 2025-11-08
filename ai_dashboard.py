#This is our second web server. Notice it runs on port=5001 so it doesn't conflict with our first dashboard.

# ai_dashboard.py
from flask import Flask, render_template, request
import ai_analyzer  # Import our new analyzer script

app = Flask(__name__)

@app.route("/", methods=['GET', 'POST'])
def dashboard():
    result = None
    if request.method == 'POST':
        # This code runs when you submit the form
        package_name = request.form.get('package_name')
        if package_name:
            result = ai_analyzer.run_ai_analysis(package_name)
    
    # This code runs on first load (GET) or after the POST
    return render_template('ai_index.html', result=result)

if __name__ == '__main__':
    # Running on port 5001 to avoid conflict with app.py (which uses 5000)
    app.run(debug=True, port=5001)