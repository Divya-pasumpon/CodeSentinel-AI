# app.py
from flask import Flask, render_template
import main  # Import all the functions from our main.py!

app = Flask(__name__)

@app.route("/") # This creates the homepage
def dashboard():
    print("--- Web Dashboard: Starting Scan ---")
    
    filepath = 'requirements.txt'
    dependencies = main.parse_requirements(filepath)
    
    analysis_results = []
    
    for package in dependencies:
        data = main.get_package_data(package)
        if data:
            latest_version = data.get('info', {}).get('version')
            score, factors = main.calculate_trust_score(data, latest_version)
            
            result = {
                "name": package,
                "score": score,
                "factors": factors
            }
            analysis_results.append(result)
        # We don't need time.sleep() here, as the user is just loading a page.
    
    print("--- Scan Complete. Calculating Stats ---")
    
    # --- Calculate Summary Statistics ---
    if analysis_results:
        # Sort by score to find the lowest
        analysis_results.sort(key=lambda x: x['score'])
        
        lowest_score = analysis_results[0]['score']
        average_score = int(sum(r['score'] for r in analysis_results) / len(analysis_results))
        package_count = len(analysis_results)
    else:
        lowest_score = "N/A"
        average_score = "N/A"
        package_count = 0

    print(f"Lowest Score: {lowest_score}, Average: {average_score}")

    # Send all our data to the HTML file
    return render_template('index.html', 
                           results=analysis_results,
                           package_count=package_count,
                           lowest_score=lowest_score,
                           average_score=average_score)

if __name__ == '__main__':
    app.run(debug=True) # Run the web server in debug mode