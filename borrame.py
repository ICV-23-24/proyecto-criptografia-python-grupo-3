from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/hola', methods=['GET', 'POST'])
def index():
    nombre = None
    if request.method == 'POST':
        nombre = request.form['nombre']
    return render_template('formulario.html', nombre=nombre)

if __name__ == '__main__':
    app.run(debug=True)
