import sys
from pathlib import Path

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from flask import Flask, render_template, request
from service import scan_target

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        options = request.form.getlist('scanner')
        try:
            report = scan_target(url, options)
        except ValueError as exc:
            return render_template('index.html', error=str(exc), url=url), 400
        return render_template('result.html', report=report, url=url)
    return render_template('index.html')


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
