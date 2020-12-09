My final project for cs50x is a Python based flask application to store and view photos and videos.
Features and Usage:
1. First time users have to sign up or if repeat users then sign in.
2. 6 pages within @login
    Index: Contains gallery of images
    Photo: Ability to view, download and delete photos
    Video: Ability to view, download and delete videos
    Upload: upload photos and videos. Only file extensions for images and videos are allowed. Interface implemented with dropzone.js
    My Account: Option to change password
    Log Out: Log out of account
3. Usage: cmd: flask run. if "app.py" file not detected message. Use set FLASK_APP=application.py