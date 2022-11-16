actionElement = document.querySelector("#action");
formElement = document.querySelector(".request-form");
clearFormHtml = formElement.innerHTML;

const clearForm = () => {
    console.log(formElement, formElement.children);
    [...formElement.children].forEach((child) => {
        if (!child.classList.contains("action")) formElement.removeChild(child);
    });
};

const createUserElement = () => {
    const createUserForm = document.createElement("div");
    createUserForm.classList.add("create-user-form");
    createUserForm.innerHTML = `
        <br/>
        <label for="name">Name</label>
        <input type="text" name="name" id="name">
        </input>
        <br/>
        <label for="privilege_level">Privilege Level</label>
        <input type="number" name="privilege_level" id="privilege_level" min="0" max="5">
        </input>
        <br/>
        <label for="type">Type</label>
        <select name="type" id="type">
            <option value="patient">Patient</option>
            <option value="doctor">Doctor</option>
        </select>
        <br/>
        <input type="submit" value="Create User" class="submit">
        </input>
    `;
    return createUserForm;
};

const deleteUserElement = () => {
    const deleteUserForm = document.createElement("div");
    deleteUserForm.classList.add("delete-user-form");
    deleteUserForm.innerHTML = `
        <br/>
        <label for="public_key">Public Key</label>
        <input type="number" name="public_key" id="public_key">
        </input>
        <br/>
        <label for="private_key">Private Key</label>
        <input type="number" name="private_key" id="private_key">
        </input>
        <br/>
        <input type="submit" value="Delete User" class="submit">
        </input>
    `;
    return deleteUserForm;
};

const diagnoseElement = () => {
    const diagnoseForm = document.createElement("div");
    diagnoseForm.classList.add("diagnose-form");
    diagnoseForm.innerHTML = `
        <br/>
        <label for="doc_public_key">Doctor Public Key</label>
        <input type="number" name="doc_public_key" id="doc_public_key">
        </input>
        <br/>
        <label for="doc_private_key">Doctor Private Key</label>
        <input type="number" name="doc_private_key" id="doc_private_key">
        </input>
        <br/>
        <label for="public_key">Public Key</label>
        <input type="number" name="public_key" id="public_key">
        </input>
        <br/>
        <label for="diagnosis">Diagnosis</label>
        <input type="text" name="diagnosis" id="diagnosis">
        </input>
        <br/>
        <input type="submit" value="Add Diagnosis" class="submit">
        </input>
    `;
    return diagnoseForm;
};

const readElement = () => {
    const readForm = document.createElement("div");
    readForm.classList.add("read-form");
    readForm.innerHTML = `
        <br/>
        <label for="public_key">Public Key</label>
        <input type="number" name="public_key" id="public_key">
        </input>
        <br/>
        <input type="submit" value="Read Records" class="submit">
        </input>
    `;
    return readForm;
};

const syntaxHighlight = (json) => {
    if (typeof json != 'string') {
         json = JSON.stringify(json, null, 2);
    }
    json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,  (match) => {
        var cls = 'number';
        if (/^"/.test(match)) {
            if (/:$/.test(match)) {
                cls = 'key';
            } else {
                cls = 'string';
            }
        } else if (/true|false/.test(match)) {
            cls = 'boolean';
        } else if (/null/.test(match)) {
            cls = 'null';
        }
        return '<span class="' + cls + '">' + match + '</span>';
    });
}

const handleFormSubmit = async (e) => {
    e.preventDefault();
    // make post request with request body
    const formData = new FormData(e.target)
    const formJson = {};
    [...formData.entries()].forEach((key_value) => {
        const [key, value] = key_value
        formJson[key] = value
    })
    const response = await fetch("/blockchain", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify(formJson),
    });
    console.log(response);
    const type = response.headers.get("Content-Type");
    console.log(type)
    if (type.includes("application/json")) {
        const responseBody = await response.json();
        console.log(responseBody);
        document.querySelector('.response-content').innerHTML = syntaxHighlight(responseBody);
    } else if (type.includes("text/html")) {
        const responseHTML = await response.text();
        console.log(responseHTML);
    }
};

actionElement.addEventListener("change", (e) => {
    console.log(e.target.value);
    clearForm();
    switch (e.target.value) {
        case "create_user":
            formElement.appendChild(createUserElement());
            formElement.addEventListener("submit", handleFormSubmit);
            break;
        case "delete_user":
            formElement.appendChild(deleteUserElement());
            formElement.addEventListener("submit", handleFormSubmit);
            break;
        case "diagnose":
            formElement.appendChild(diagnoseElement());
            formElement.addEventListener("submit", handleFormSubmit);
            break;
        case "read":
            formElement.appendChild(readElement());
            formElement.addEventListener("submit", handleFormSubmit);
            break;
        default:
            break;
    }
});
