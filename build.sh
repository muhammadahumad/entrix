#!/usr/bin/env bash
set -o errexit
pip install -r requirements.txt
python -c "from app import app, db; app.app_context().push(); db.create_all(); print('Database ready')"
