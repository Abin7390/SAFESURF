from flask import Flask, render_template, request
from main import main_function

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')
@app.route('/index')
def index1():
    return render_template('index.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/form', methods=['GET', 'POST'])
def form():
    # def truncate_filter(text, max_length=32):
    #     """Truncate the text to max_length and add '...' if necessary."""
    #     if len(text) > max_length:
    #         return text[:max_length] + '...'
    #     return text
    
    url = request.form.get('url')
    
    result, Url, filepath = main_function(url)
    print("1")
    print(result)
   
    # urls = truncate_filter(Url)
    urls = Url
    return render_template('home.html', result=result, Url=urls, Filepath = filepath)

if __name__ == "__main__":
    app.run(debug=True)
