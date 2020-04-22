def login_filter(login):
    login = str(login).replace("'", "").replace(" ", "")
    if len(login) > 40:
        return None
    else:
        return login


def password_filter(password):
    password = str(password).replace("'", "").replace(" ","")
    if len(password) > 30:
        return None
    else:
        return password


