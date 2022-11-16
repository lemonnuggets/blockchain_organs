from flask import Flask, redirect, render_template, request

from blockchain.blockchain import BlockchainDB

app = Flask(__name__)

db = BlockchainDB("app")


@app.route("/")
def index():
    return redirect("/home")


@app.route("/home")
def home():
    return render_template("home.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/blockchain", methods=["GET", "POST"])
def blockchain():
    if request.method == "POST":
        print(request, request.get_data())
        content = {}
        if request.is_json:
            print("request.json")
            content = request.get_json()
        else:
            print("request.form")
            content = request.form.to_dict()
        print(content)
        if content["action"] == "create_user":
            print("create user")
            return db.add_user(
                content["name"],
                content["type"],
            )
        if content["action"] == "delete_user":
            print("delete user")
            return db.delete_user(
                int(content["public_key"]),
                int(content["private_key"]),
            )
        if content["action"] == "donate":
            print("donate")
            return db.add_donation(
                doctor_private_key=int(content["doc_private_key"]),
                doctor_public_key=int(content["doc_public_key"]),
                donor_public_key=int(content["public_key"]),
                organ_type=content["organ_type"],
            )
        if content["action"] == "recieve":
            print("recieve")
            return db.add_recieve_record(
                doctor_public_key=int(content["doc_public_key"]),
                doctor_private_key=int(content["doc_private_key"]),
                patient_public_key=int(content["public_key"]),
                organ_type=content["organ_type"],
            )
            # if content["action"] == "read":
            #     print("read")
            #     return db.read_records(int(content["public_key"]))
    return render_template("blockchain.html")


if __name__ == "__main__":
    app.run(debug=True)
