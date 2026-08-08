client_secret = "demo-secret-that-must-never-be-committed"


def handler(event):
    return {"accepted": True, "event": event}
