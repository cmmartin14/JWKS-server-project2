# JWKS-server-project2

<img width="1104" height="323" alt="Screenshot 2025-10-26 at 7 26 30 PM" src="https://github.com/user-attachments/assets/428aa6a5-5ee4-47f6-8bda-cedc205b4eea" />

### AI Use Summary

I used AI to help me update my project 1 code to open the totally_not_my_privateKeys.db file at the start, figure out how to write my private keys to the file, and learn how to modify the POST:/auth and GET:/.well-known/jwks.json endpoints to use the database. I also asked it to help me fix errors I got when I ran my code against the grade bot.

### Prompts

1. I'm working on updating a project to extend a JWKS server using SQLite. Wait for me to give you the code for each of my existing files from the previous project that need to be updated to fit the new project's requirements. This is what I need to add to the new project: create/open a SQLite DB file at start, write your private keys to that file, modify the POST:/auth and GET:/.well-known/jwks.json endpoints to use the database.
2. Here is my current code for main.py. How can I go about implementing the requirements from the previous prompt?
3. When I run my code against the grade bot, I get these debug messages. What could be going wrong here? time=2025-10-26T17:15:57.364-05:00 level=ERROR msg="/auth valid JWT authN" err="Post \"http://127.0.0.1:8080/auth\": dial tcp 127.0.0.1:8080: connect: connection refused"
time=2025-10-26T17:15:57.364-05:00 level=ERROR msg="Valid JWK found in JWKS" err="no valid JWT found"
time=2025-10-26T17:15:57.364-05:00 level=ERROR msg="Database exists" err="stat totally_not_my_privateKeys.db: no such file or directory"
