# ExamPortal

## Run it (Windows)
Double-click **run.bat**. 
First run it creates a virtual environment and installs everything automatically
(needs Python 3.9+; if missing, the script tries to install it via winget). Your browser opens
at http://localhost:5000.

Data is stored in MongoDB (database `examportal`). All settings live in **.env**.

## MongoDB Atlas checklist
- Atlas -> **Network Access** -> add your IP (or `0.0.0.0/0` for anywhere). Without this, connection fails.
- Credentials are in `.env` (`MONGODB_URI`). Never share or commit that file.

## Optional: Email OTP / Google Login
Fill the `SMTP_*` and `GOOGLE_*` values in `.env`. If left as-is, OTP codes are printed in the console
window and the Google button is hidden.

## Mac / Linux
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python app.py
```

## Collections
users, otp_codes, student_groups, tests, questions, test_assignments, attempts, counters

## CSV import format
```csv
question1,answer,marks,option1,option2,option3,option4
What is 2+2?,2,1,2,4,6,8
```
