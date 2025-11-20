# 1) create and activate venv
python3 -m venv .venv
source .venv/bin/activate

# 2) install dependencies
pip install fastapi "uvicorn[standard]" pydantic

# 3A) Option: run from inside the `src` folder (most straightforward)
cd src
uvicorn intent_service:app --reload --host 127.0.0.1 --port 9000

# 3B) Option: run from project root by adding `src` to PYTHONPATH
# (keeps working directory at project root)
#PYTHONPATH=src uvicorn intent_service:app --reload --host 127.0.0.1 --port 9000

# 4) Test the running service
curl -i -X POST -H "Content-Type: application/json" \
  -d '{
    "user_id":"alice",
    "role":"fraud_analyst",
    "permissions":["read_customer_data"],
    "action":"read",
    "mfa_authenticated":true,
    "device_trusted":true,
    "last_access":"2025-11-20T12:00:00Z",
    "location":"NL",
    "network":"office"
  }' \
  http://127.0.0.1:9000/verify-intent
