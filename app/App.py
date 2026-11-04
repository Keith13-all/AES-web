from flask import Flask, render_template, request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__, template_folder="../html", static_folder="../css")

@app.route("/", methods=["GET", "POST"])
def index():
    result = ""
    error = ""
    content = ""
    key_value = ""

    if request.method == "POST":
        content = request.form.get("content", "")
        key_value = request.form.get("key", "")
        mode = request.form.get("mode", "")

        try:
            key = key_value.encode("utf-8")

            if len(key) != 16:
                raise ValueError("Key phải có đúng 16 byte!")

            if mode == "encrypt":
                cipher = AES.new(key, AES.MODE_ECB)

                data = content.encode("utf-8")
                padded_data = pad(data, AES.block_size)

                encrypted = cipher.encrypt(padded_data)
                result = encrypted.hex()

            elif mode == "decrypt":
                encrypted = bytes.fromhex(content)

                if not encrypted or len(encrypted) % 16 != 0:
                    raise ValueError("Ciphertext không hợp lệ!")

                cipher = AES.new(key, AES.MODE_ECB)

                decrypted = cipher.decrypt(encrypted)
                result = unpad(
                    decrypted, AES.block_size
                ).decode("utf-8")

        except (ValueError, UnicodeDecodeError) as e:
            error = str(e)

    return render_template(
        "index.html",
        result=result,
        error=error,
        content=content,
        key=key_value
    )

if __name__ == "__main__":
    app.run(debug=True)