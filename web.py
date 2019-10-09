from flask import *
import json
app = Flask(__name__)


data = []


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        jsoned = json.loads(request.data)
        data.append(jsoned['issue'])
        print(data)
        return 'ok'
    else:
        return render_template('index.html', data=data)


if __name__ == "__main__":
    app.run(debug=True)
