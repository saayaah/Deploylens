# Intentionally insecure demo fixture. The key below is FAKE and exists only to exercise the scanner.
API_KEY = "demo_sk_live_0123456789abcdef"
DEBUG = True


class Settings:
    api_key = API_KEY
    debug = DEBUG


settings = Settings()
