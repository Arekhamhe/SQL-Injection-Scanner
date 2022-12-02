from flask import Flask, render_template, request
from scan import sql_injection_scan


app = Flask(__name__)


@app.route("/", methods=['GET', 'POST'])
def index():
    template_name = "index.html"
    if request.method == 'POST':
        url = request.form['url']
        responses = sql_injection_scan(url)
        return render_template(template_name, **{"responses": responses})
    return render_template(template_name)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)